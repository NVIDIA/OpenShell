// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E regression: WebSocket credential placeholders are resolved on the real
//! Docker-backed sandbox path after an RFC 6455 upgrade.
//!
//! The sandbox process sends its provider-managed placeholder in a masked text
//! frame. The local upstream only reports whether it saw the real secret and
//! whether any placeholder survived; it never echoes payload bytes, placeholder
//! text, or secret material back into test output.

use std::io::Write;
use std::process::Stdio;
use std::sync::Mutex;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::ContainerHttpServer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const PROVIDER_NAME: &str = "e2e-websocket-conformance";
const TEST_SERVER_ALIAS: &str = "websocket-conformance.openshell.test";
const TEST_SECRET: &str = "sk-e2e-websocket-conformance-secret";
const TOKEN_ENV: &str = "WS_E2E_TOKEN";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";
static PROVIDER_LOCK: Mutex<()> = Mutex::new(());

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("failed to spawn openshell {}: {e}", args.join(" ")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let combined = format!("{stdout}{stderr}");

    if !output.status.success() {
        return Err(format!(
            "openshell {} failed (exit {:?}):\n{combined}",
            args.join(" "),
            output.status.code()
        ));
    }

    Ok(combined)
}

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("provider")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let _ = cmd.status().await;
}

async fn create_generic_provider(name: &str) -> Result<String, String> {
    let credential = format!("{TOKEN_ENV}={TEST_SECRET}");
    run_cli(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        "generic",
        "--credential",
        &credential,
    ])
    .await
}

async fn start_websocket_probe_server() -> Result<ContainerHttpServer, String> {
    let script = format!(
        r#"
import base64
import hashlib
import json
import socketserver
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SECRET = {secret:?}
PLACEHOLDER_PREFIX = {placeholder_prefix:?}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected end of websocket frame")
        data += chunk
    return data

def read_frame(sock):
    header = read_exact(sock, 2)
    first, second = header[0], header[1]
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if second & 0x80 else b""
    payload = read_exact(sock, length)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first, payload

def send_text(sock, payload):
    data = payload.encode("utf-8")
    if len(data) < 126:
        header = bytes([0x81, len(data)])
    elif len(data) <= 0xFFFF:
        header = bytes([0x81, 126]) + struct.pack("!H", len(data))
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", len(data))
    sock.sendall(header + data)

def header_value(request, name):
    prefix = name.lower() + ":"
    for line in request.split("\r\n"):
        if line.lower().startswith(prefix):
            return line.split(":", 1)[1].strip()
    return ""

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        request_bytes = recv_until(self.request, b"\r\n\r\n")
        request = request_bytes.decode("iso-8859-1", "replace")
        if "upgrade: websocket" not in request.lower():
            self.request.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            return

        key = header_value(request, "Sec-WebSocket-Key")
        accept = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {{accept}}\r\n"
            "\r\n"
        )
        self.request.sendall(response.encode("ascii"))

        _, payload = read_frame(self.request)
        text = payload.decode("utf-8", "replace")
        result = {{
            "saw_placeholder": PLACEHOLDER_PREFIX in text,
            "saw_secret": SECRET in text,
        }}
        send_text(self.request, json.dumps(result, sort_keys=True))

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

Server(("0.0.0.0", 8000), Handler).serve_forever()
"#,
        secret = TEST_SECRET,
        placeholder_prefix = PLACEHOLDER_PREFIX,
    );

    ContainerHttpServer::start_python(TEST_SERVER_ALIAS, &script).await
}

fn write_websocket_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
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
  websocket_conformance:
    name: websocket_conformance
    endpoints:
      - host: {host}
        port: {port}
        protocol: websocket
        enforcement: enforce
        access: read-write
        websocket_credential_rewrite: true
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
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

fn websocket_client_script(host: &str, port: u16) -> String {
    format!(
        r#"
import base64
import json
import os
import socket
import struct

HOST = {host:?}
PORT = {port}
TOKEN_ENV = {token_env:?}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def read_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("unexpected end of websocket frame")
        data += chunk
    return data

def masked_text_frame(payload):
    data = payload.encode("utf-8")
    mask = os.urandom(4)
    if len(data) < 126:
        header = bytes([0x81, 0x80 | len(data)])
    elif len(data) <= 0xFFFF:
        header = bytes([0x81, 0x80 | 126]) + struct.pack("!H", len(data))
    else:
        header = bytes([0x81, 0x80 | 127]) + struct.pack("!Q", len(data))
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
    return header + mask + masked

def read_frame(sock):
    first, second = read_exact(sock, 2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(sock, 8))[0]
    mask = read_exact(sock, 4) if second & 0x80 else b""
    payload = read_exact(sock, length)
    if mask:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return first, payload

token = os.environ[TOKEN_ENV]
payload = json.dumps({{"authorization": "Bearer " + token}}, sort_keys=True)
key = base64.b64encode(os.urandom(16)).decode("ascii")

with socket.create_connection((HOST, PORT), timeout=20) as sock:
    request = (
        f"GET /ws HTTP/1.1\r\n"
        f"Host: {{HOST}}:{{PORT}}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {{key}}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(request.encode("ascii"))
    response = recv_until(sock, b"\r\n\r\n").decode("iso-8859-1", "replace")
    if not response.startswith("HTTP/1.1 101"):
        raise RuntimeError("websocket upgrade failed")
    sock.sendall(masked_text_frame(payload))
    _, response_payload = read_frame(sock)
    print(response_payload.decode("utf-8"))
"#,
        host = host,
        port = port,
        token_env = TOKEN_ENV,
    )
}

#[tokio::test]
async fn websocket_text_placeholder_is_rewritten_in_docker_sandbox() {
    let _provider_lock = PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    delete_provider(PROVIDER_NAME).await;
    create_generic_provider(PROVIDER_NAME)
        .await
        .expect("create generic provider");

    let result = async {
        let server = start_websocket_probe_server().await?;
        let policy = write_websocket_policy(&server.host, server.port)?;
        let policy_path = policy
            .path()
            .to_str()
            .ok_or_else(|| "temp policy path should be utf-8".to_string())?
            .to_string();
        let script = websocket_client_script(&server.host, server.port);

        SandboxGuard::create(&[
            "--policy",
            &policy_path,
            "--provider",
            PROVIDER_NAME,
            "--",
            "python3",
            "-c",
            &script,
        ])
        .await
    }
    .await;

    delete_provider(PROVIDER_NAME).await;

    let guard = result.expect("sandbox create");
    assert!(
        guard
            .create_output
            .contains(r#"{"saw_placeholder": false, "saw_secret": true}"#),
        "expected upstream to see only the resolved secret marker:\n{}",
        guard.create_output
    );
    assert!(
        !guard.create_output.contains(TEST_SECRET),
        "test output should not expose the raw WebSocket credential:\n{}",
        guard.create_output
    );
    assert!(
        !guard.create_output.contains(PLACEHOLDER_PREFIX),
        "test output should not expose unresolved credential placeholders:\n{}",
        guard.create_output
    );
}
