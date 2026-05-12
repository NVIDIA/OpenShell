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

use std::io::{self, Error, ErrorKind, Write};
use std::process::Stdio;
use std::sync::Mutex;

use base64::Engine as _;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use sha1::{Digest, Sha1};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const PROVIDER_NAME: &str = "e2e-websocket-conformance";
const TEST_SERVER_HOST: &str = "host.openshell.internal";
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

struct WebSocketProbeServer {
    port: u16,
    task: JoinHandle<()>,
}

impl WebSocketProbeServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|e| format!("bind websocket probe server: {e}"))?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("read websocket probe server address: {e}"))?
            .port();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = handle_websocket_probe_connection(stream).await;
                });
            }
        });

        Ok(Self { port, task })
    }
}

impl Drop for WebSocketProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn recv_until(stream: &mut TcpStream, marker: &[u8]) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buf).await?;
        if read == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buf[..read]);
        if data.windows(marker.len()).any(|window| window == marker) {
            return Ok(data);
        }
    }
}

async fn read_websocket_text(stream: &mut TcpStream) -> io::Result<String> {
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).await?;
    let length = match header[1] & 0x7F {
        len @ 0..=125 => usize::from(len),
        126 => {
            let mut bytes = [0_u8; 2];
            stream.read_exact(&mut bytes).await?;
            usize::from(u16::from_be_bytes(bytes))
        }
        127 => {
            let mut bytes = [0_u8; 8];
            stream.read_exact(&mut bytes).await?;
            usize::try_from(u64::from_be_bytes(bytes))
                .map_err(|_| Error::new(ErrorKind::InvalidData, "websocket frame too large"))?
        }
        _ => unreachable!(),
    };

    let mut mask = [0_u8; 4];
    if header[1] & 0x80 != 0 {
        stream.read_exact(&mut mask).await?;
    } else {
        mask = [0, 0, 0, 0];
    }

    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload).await?;
    if header[1] & 0x80 != 0 {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
    }

    String::from_utf8(payload).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("invalid websocket text: {e}"),
        )
    })
}

async fn send_websocket_text(stream: &mut TcpStream, payload: &str) -> io::Result<()> {
    let data = payload.as_bytes();
    let mut frame = Vec::with_capacity(data.len() + 10);
    frame.push(0x81);
    if data.len() < 126 {
        frame.push(
            u8::try_from(data.len())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "websocket frame too large"))?,
        );
    } else if data.len() <= usize::from(u16::MAX) {
        frame.push(126);
        frame.extend_from_slice(
            &u16::try_from(data.len())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "websocket frame too large"))?
                .to_be_bytes(),
        );
    } else {
        frame.push(127);
        frame.extend_from_slice(
            &u64::try_from(data.len())
                .map_err(|_| Error::new(ErrorKind::InvalidData, "websocket frame too large"))?
                .to_be_bytes(),
        );
    }
    frame.extend_from_slice(data);
    stream.write_all(&frame).await
}

fn header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        if header.trim().eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn websocket_accept_for_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

async fn handle_websocket_probe_connection(mut stream: TcpStream) -> io::Result<()> {
    let request_bytes = recv_until(&mut stream, b"\r\n\r\n").await?;
    let request = String::from_utf8_lossy(&request_bytes);
    if !request.to_ascii_lowercase().contains("upgrade: websocket") {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        return Ok(());
    }

    let accept = header_value(&request, "Sec-WebSocket-Key")
        .map(|key| websocket_accept_for_key(&key))
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "missing Sec-WebSocket-Key"))?;
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await?;

    let text = read_websocket_text(&mut stream).await?;
    let response = format!(
        r#"{{"saw_placeholder": {}, "saw_secret": {}}}"#,
        text.contains(PLACEHOLDER_PREFIX),
        text.contains(TEST_SECRET)
    );
    send_websocket_text(&mut stream, &response).await
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
import time
import urllib.parse

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

def proxy_parts():
    names = ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")
    proxy_url = next((os.environ.get(name) for name in names if os.environ.get(name)), None)
    if not proxy_url:
        raise RuntimeError("proxy environment is not configured")
    parsed = urllib.parse.urlparse(proxy_url)
    if not parsed.hostname:
        raise RuntimeError(f"invalid proxy URL: {{proxy_url!r}}")
    return parsed.hostname, parsed.port or 80

def connect_with_retry(host, port, timeout_seconds=20):
    proxy_host, proxy_port = proxy_parts()
    target = f"{{host}}:{{port}}"
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while time.monotonic() < deadline:
        sock = None
        try:
            sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
            request = f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n"
            sock.sendall(request.encode("ascii"))
            response = recv_until(sock, b"\r\n\r\n").decode("iso-8859-1", "replace")
            if response.startswith("HTTP/1.1 200") or response.startswith("HTTP/1.0 200"):
                return sock
            first_line = response.splitlines()[0] if response else "<empty response>"
            raise RuntimeError(f"proxy CONNECT failed: {{first_line}}")
        except (OSError, RuntimeError) as error:
            if sock is not None:
                sock.close()
            last_error = error
            time.sleep(0.25)
    raise last_error

token = os.environ[TOKEN_ENV]
payload = json.dumps({{"authorization": "Bearer " + token}}, sort_keys=True)
key = base64.b64encode(os.urandom(16)).decode("ascii")

with connect_with_retry(HOST, PORT) as sock:
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
        let server = WebSocketProbeServer::start().await?;
        let policy = write_websocket_policy(TEST_SERVER_HOST, server.port)?;
        let policy_path = policy
            .path()
            .to_str()
            .ok_or_else(|| "temp policy path should be utf-8".to_string())?
            .to_string();
        let script = websocket_client_script(TEST_SERVER_HOST, server.port);

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
