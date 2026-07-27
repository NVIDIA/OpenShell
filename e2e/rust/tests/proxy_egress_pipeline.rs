// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for the shared explicit-proxy egress pipeline.
//!
//! These tests exercise behavior that must remain identical while CONNECT and
//! forward HTTP converge on shared authorization, destination, and relay
//! primitives:
//! - live policy reloads affect new requests through both adapters and close a
//!   pre-existing CONNECT HTTP stream before its next request is forwarded;
//! - `tls: skip` selects a byte-transparent TCP relay;
//! - provider placeholders in HTTP headers and opted-in REST bodies are
//!   resolved through both adapters without appearing in test output.

use std::io::{self, Error, ErrorKind, Write};
use std::process::Stdio;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const TEST_SERVER_HOST: &str = "host.openshell.internal";
const PROVIDER_NAME: &str = "e2e-proxy-egress-credentials";
const TOKEN_ENV: &str = "PROXY_E2E_TOKEN";
const TEST_SECRET: &str = "sk-e2e-proxy-egress-secret";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";
const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;
static PROVIDER_LOCK: Mutex<()> = Mutex::new(());

async fn run_cli(args: &[&str]) -> Result<String, String> {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .await
        .map_err(|error| format!("failed to spawn openshell {}: {error}", args.join(" ")))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
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

async fn wait_for_sandbox_logs(
    sandbox_name: &str,
    expected: impl Fn(&str) -> bool,
) -> Result<String, String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);

    loop {
        let logs = run_cli(&[
            "logs",
            sandbox_name,
            "-n",
            "500",
            "--since",
            "2m",
            "--source",
            "sandbox",
        ])
        .await?;
        if expected(&logs) {
            return Ok(logs);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for expected sandbox logs:\n{logs}"
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

async fn delete_provider(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.args(["provider", "delete", name])
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

fn write_policy_document(
    host: &str,
    port: u16,
    endpoint_options: &str,
    network_middlewares: &str,
) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
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

{network_middlewares}
network_policies:
  proxy_egress_test:
    name: proxy_egress_test
    endpoints:
      - host: {host}
        port: {port}
{endpoint_options}
{PRIVATE_ALLOWED_IPS}
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn write_policy(host: &str, port: u16, endpoint_options: &str) -> Result<NamedTempFile, String> {
    write_policy_document(host, port, endpoint_options, "")
}

fn write_middleware_policy(
    host: &str,
    port: u16,
    endpoint_options: &str,
    on_error: &str,
) -> Result<NamedTempFile, String> {
    let network_middlewares = format!(
        r#"network_middlewares:
  regex-redactor:
    name: Redact API tokens
    middleware: openshell/regex
    order: 10
    config:
      mode: redact
    on_error: {on_error}
    endpoints:
      include: ["{host}"]
      exclude: []
"#
    );
    write_policy_document(host, port, endpoint_options, &network_middlewares)
}

fn write_denied_policy() -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = r#"version: 1

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

network_policies: {}
"#;
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn write_ambiguous_policy(host: &str, port: u16) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
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
  terminating:
    name: terminating
    endpoints:
      - host: {host}
        port: {port}
{PRIVATE_ALLOWED_IPS}
    binaries:
      - path: "/**"
  passthrough:
    name: passthrough
    endpoints:
      - host: {host}
        port: {port}
        tls: skip
{PRIVATE_ALLOWED_IPS}
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn write_destination_denial_policy() -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let policy = r#"version: 1

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
  destination_denials:
    name: destination_denials
    endpoints:
      - { host: 169.254.169.254, port: 80 }
      - { host: 127.0.0.1, port: 80 }
      - { host: 203.0.113.10, port: 6443 }
      - host: 203.0.113.10
        port: 8080
        allowed_ips: ["198.51.100.0/24"]
    binaries:
      - path: "/**"
"#;
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn write_ip_literal_success_policy(
    ip: &str,
    explicit_port: u16,
    implicit_port: u16,
) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
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
  destination_successes:
    name: destination_successes
    endpoints:
      - host: {ip}
        port: {explicit_port}
        allowed_ips: ["{ip}/32"]
      - host: {ip}
        port: {implicit_port}
    binaries:
      - path: "/**"
"#
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

fn policy_path(file: &NamedTempFile) -> String {
    file.path()
        .to_str()
        .expect("temporary policy path should be utf-8")
        .to_string()
}

async fn read_until(stream: &mut TcpStream, marker: &[u8]) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(data);
        }
        data.extend_from_slice(&buffer[..read]);
        if data.windows(marker.len()).any(|window| window == marker) {
            return Ok(data);
        }
    }
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length(headers: &[u8]) -> io::Result<usize> {
    let text =
        std::str::from_utf8(headers).map_err(|error| Error::new(ErrorKind::InvalidData, error))?;
    Ok(text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0))
}

async fn read_http_request(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut request = read_until(stream, b"\r\n\r\n").await?;
    if request.is_empty() {
        return Ok(None);
    }
    let headers_end = header_end(&request)
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP headers"))?;
    let body_length = content_length(&request[..headers_end])?;
    let total_length = headers_end + body_length;
    while request.len() < total_length {
        let mut buffer = vec![0_u8; total_length - request.len()];
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP body"));
        }
        request.extend_from_slice(&buffer[..read]);
    }
    request.truncate(total_length);
    Ok(Some(request))
}

struct KeepAliveHttpServer {
    port: u16,
    connections: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl KeepAliveHttpServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind HTTP server: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read HTTP server address: {error}"))?
            .port();
        let connections = Arc::new(AtomicUsize::new(0));
        let task_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                task_connections.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    let _ = handle_keep_alive_connection(stream).await;
                });
            }
        });
        Ok(Self {
            port,
            connections,
            task,
        })
    }

    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::Acquire)
    }
}

impl Drop for KeepAliveHttpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_keep_alive_connection(mut stream: TcpStream) -> io::Result<()> {
    while let Some(request) = read_http_request(&mut stream).await? {
        let close = String::from_utf8_lossy(&request)
            .lines()
            .any(|line| line.eq_ignore_ascii_case("connection: close"));
        let connection = if close { "close" } else { "keep-alive" };
        let response =
            format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: {connection}\r\n\r\nok");
        stream.write_all(response.as_bytes()).await?;
        if close {
            return Ok(());
        }
    }
    Ok(())
}

struct EchoServer {
    port: u16,
    observed: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

struct RequestBodyEchoServer {
    port: u16,
    task: JoinHandle<()>,
}

impl RequestBodyEchoServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind request body echo server: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read request body echo server address: {error}"))?
            .port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = handle_request_body_echo(stream).await;
                });
            }
        });
        Ok(Self { port, task })
    }
}

impl Drop for RequestBodyEchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_request_body_echo(mut stream: TcpStream) -> io::Result<()> {
    let request = read_http_request(&mut stream)
        .await?
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "missing HTTP request"))?;
    let headers_end = header_end(&request)
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP headers"))?;
    let body = &request[headers_end..];
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await
}

struct PipelineProbeServer {
    port: u16,
    observed: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl PipelineProbeServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind pipeline probe: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read pipeline probe address: {error}"))?
            .port();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let observed_task = observed.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let observed = observed_task.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buffer = [0_u8; 4096];
                    loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_millis(200),
                            stream.read(&mut buffer),
                        )
                        .await
                        {
                            Ok(Ok(0)) | Err(_) => break,
                            Ok(Ok(read)) => request.extend_from_slice(&buffer[..read]),
                            Ok(Err(_)) => return,
                        }
                    }
                    observed.lock().unwrap().extend_from_slice(&request);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                });
            }
        });
        Ok(Self {
            port,
            observed,
            task,
        })
    }

    fn observed_request(&self) -> Vec<u8> {
        self.observed.lock().unwrap().clone()
    }
}

impl Drop for PipelineProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EchoServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind echo server: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read echo server address: {error}"))?
            .port();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let task_observed = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let observed = Arc::clone(&task_observed);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    loop {
                        let Ok(read) = stream.read(&mut buffer).await else {
                            break;
                        };
                        if read == 0 {
                            break;
                        }
                        observed.lock().unwrap().extend_from_slice(&buffer[..read]);
                        if stream.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Ok(Self {
            port,
            observed,
            task,
        })
    }

    fn observed_bytes(&self) -> Vec<u8> {
        self.observed.lock().unwrap().clone()
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct CredentialProbeServer {
    port: u16,
    task: JoinHandle<()>,
}

impl CredentialProbeServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind credential probe: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read credential probe address: {error}"))?
            .port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = handle_credential_probe(stream).await;
                });
            }
        });
        Ok(Self { port, task })
    }
}

impl Drop for CredentialProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle_credential_probe(mut stream: TcpStream) -> io::Result<()> {
    let request = read_http_request(&mut stream)
        .await?
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "missing HTTP request"))?;
    let headers_end = header_end(&request)
        .ok_or_else(|| Error::new(ErrorKind::UnexpectedEof, "incomplete HTTP headers"))?;
    let headers = String::from_utf8_lossy(&request[..headers_end]);
    let expected_authorization = format!("Bearer {TEST_SECRET}");
    let header_resolved = headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("authorization") && value.trim() == expected_authorization
        })
    });
    let body_resolved = request[headers_end..]
        .windows(TEST_SECRET.len())
        .any(|window| window == TEST_SECRET.as_bytes());
    let saw_placeholder = request
        .windows(PLACEHOLDER_PREFIX.len())
        .any(|window| window == PLACEHOLDER_PREFIX.as_bytes());
    let body = serde_json::json!({
        "body_resolved": body_resolved,
        "header_resolved": header_resolved,
        "saw_placeholder": saw_placeholder,
    })
    .to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

fn proxy_status_script(host: &str, port: u16) -> String {
    format!(
        r#"
import json
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}

def proxy_parts():
    proxy_url = next(
        os.environ[name]
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
        if os.environ.get(name)
    )
    parsed = urllib.parse.urlparse(proxy_url)
    return parsed.hostname, parsed.port or 80

def read_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def status(response):
    parts = response.split(None, 2)
    return int(parts[1]) if len(parts) > 1 else 0

def forward_status():
    proxy_host, proxy_port = proxy_parts()
    target = f"{{HOST}}:{{PORT}}"
    with socket.create_connection((proxy_host, proxy_port), timeout=10) as sock:
        sock.sendall(
            f"GET http://{{target}}/forward HTTP/1.1\r\n"
            f"Host: {{target}}\r\nConnection: close\r\n\r\n".encode()
        )
        return status(read_headers(sock))

def connect_status():
    proxy_host, proxy_port = proxy_parts()
    target = f"{{HOST}}:{{PORT}}"
    with socket.create_connection((proxy_host, proxy_port), timeout=10) as sock:
        sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
        code = status(read_headers(sock))
        if code != 200:
            return code
        sock.sendall(
            f"GET /connect HTTP/1.1\r\nHost: {{target}}\r\nConnection: close\r\n\r\n".encode()
        )
        return status(read_headers(sock))

print(json.dumps({{"connect": connect_status(), "forward": forward_status()}}, sort_keys=True))
"#,
        host = host,
        port = port,
    )
}

fn persistent_connect_script(host: &str, port: u16) -> String {
    format!(
        r#"
import json
import os
import socket
import time
import urllib.parse

HOST = {host:?}
PORT = {port}
READY = "/tmp/proxy-reload-ready"
GO = "/tmp/proxy-reload-go"
RESULT = "/tmp/proxy-reload-result"

def proxy_parts():
    proxy_url = next(
        os.environ[name]
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
        if os.environ.get(name)
    )
    parsed = urllib.parse.urlparse(proxy_url)
    return parsed.hostname, parsed.port or 80

def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return 0
        data += chunk
    headers, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            return 0
        body += chunk
    return int(headers.split(None, 2)[1])

proxy_host, proxy_port = proxy_parts()
target = f"{{HOST}}:{{PORT}}"
failed_closed = False
second_status = 0
try:
    with socket.create_connection((proxy_host, proxy_port), timeout=10) as sock:
        sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
        if read_response(sock) != 200:
            raise RuntimeError("initial CONNECT was denied")
        sock.sendall(
            f"GET /before-reload HTTP/1.1\r\nHost: {{target}}\r\nConnection: keep-alive\r\n\r\n".encode()
        )
        if read_response(sock) != 200:
            raise RuntimeError("initial tunneled request was denied")
        open(READY, "w").close()
        deadline = time.monotonic() + 120
        while not os.path.exists(GO) and time.monotonic() < deadline:
            time.sleep(0.1)
        if not os.path.exists(GO):
            raise RuntimeError("timed out waiting for policy reload signal")
        try:
            sock.sendall(
                f"GET /after-reload HTTP/1.1\r\nHost: {{target}}\r\nConnection: close\r\n\r\n".encode()
            )
            second_status = read_response(sock)
        except OSError:
            second_status = 0
        failed_closed = second_status != 200
finally:
    with open(RESULT, "w") as result:
        json.dump({{"failed_closed": failed_closed, "second_status": second_status}}, result, sort_keys=True)
"#,
        host = host,
        port = port,
    )
}

async fn wait_for_sandbox_file(guard: &SandboxGuard, path: &str, log_path: &str) -> String {
    let script = format!(
        r#"import os, time
deadline = time.monotonic() + 60
while not os.path.exists({path:?}) and time.monotonic() < deadline:
    time.sleep(0.1)
if not os.path.exists({path:?}):
    if os.path.exists({log_path:?}):
        print(open({log_path:?}).read())
    raise SystemExit("timed out waiting for {path}")
print(open({path:?}).read())
"#
    );
    guard
        .exec(&["python3", "-c", &script])
        .await
        .unwrap_or_else(|error| panic!("wait for sandbox file {path}: {error}"))
}

fn parse_json_line(output: &str) -> Value {
    output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .next_back()
        .unwrap_or_else(|| panic!("missing JSON result in sandbox output:\n{output}"))
}

#[tokio::test]
async fn policy_reload_updates_both_adapters_and_closes_existing_http_tunnel() {
    let server = KeepAliveHttpServer::start()
        .await
        .expect("start keep-alive HTTP server");
    let policy_a = write_policy(TEST_SERVER_HOST, server.port, "").expect("write policy A");
    let policy_b = write_denied_policy().expect("write policy B");
    let policy_a_path = policy_path(&policy_a);
    let policy_b_path = policy_path(&policy_b);

    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_a_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    run_cli(&[
        "policy",
        "set",
        &guard.name,
        "--policy",
        &policy_a_path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await
    .expect("wait for policy A");

    let persistent_script = persistent_connect_script(TEST_SERVER_HOST, server.port);
    guard
        .exec(&[
            "sh",
            "-c",
            "nohup python3 -c \"$1\" >/tmp/proxy-reload-client.log 2>&1 &",
            "proxy-reload-client",
            &persistent_script,
        ])
        .await
        .expect("start persistent CONNECT client");
    wait_for_sandbox_file(
        &guard,
        "/tmp/proxy-reload-ready",
        "/tmp/proxy-reload-client.log",
    )
    .await;

    let status_script = proxy_status_script(TEST_SERVER_HOST, server.port);
    let before = guard
        .exec(&["python3", "-c", &status_script])
        .await
        .expect("exercise both adapters before reload");
    let before = parse_json_line(&before);
    assert_eq!(before["connect"], 200, "CONNECT before reload: {before}");
    assert_eq!(
        before["forward"], 200,
        "forward HTTP before reload: {before}"
    );

    run_cli(&[
        "policy",
        "set",
        &guard.name,
        "--policy",
        &policy_b_path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await
    .expect("publish and wait for policy B");

    guard
        .exec(&["sh", "-c", "touch /tmp/proxy-reload-go"])
        .await
        .expect("release persistent CONNECT client");
    let stale_tunnel = wait_for_sandbox_file(
        &guard,
        "/tmp/proxy-reload-result",
        "/tmp/proxy-reload-client.log",
    )
    .await;
    let stale_tunnel = parse_json_line(&stale_tunnel);
    assert_eq!(
        stale_tunnel["failed_closed"], true,
        "existing CONNECT HTTP stream forwarded after policy reload: {stale_tunnel}"
    );

    let after = guard
        .exec(&["python3", "-c", &status_script])
        .await
        .expect("exercise both adapters after reload");
    let after = parse_json_line(&after);
    assert_eq!(after["connect"], 403, "CONNECT after reload: {after}");
    assert_eq!(after["forward"], 403, "forward HTTP after reload: {after}");

    guard.cleanup().await;
}

#[tokio::test]
async fn ambiguous_policy_update_is_rejected_without_replacing_active_policy() {
    let server = KeepAliveHttpServer::start()
        .await
        .expect("start keep-alive HTTP server");
    let valid_policy = write_policy(TEST_SERVER_HOST, server.port, "").expect("write valid policy");
    let ambiguous_policy =
        write_ambiguous_policy(TEST_SERVER_HOST, server.port).expect("write ambiguous policy");
    let valid_policy_path = policy_path(&valid_policy);
    let ambiguous_policy_path = policy_path(&ambiguous_policy);

    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &valid_policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    run_cli(&[
        "policy",
        "set",
        &guard.name,
        "--policy",
        &valid_policy_path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await
    .expect("wait for valid policy");

    let status_script = proxy_status_script(TEST_SERVER_HOST, server.port);
    let before = guard
        .exec(&["python3", "-c", &status_script])
        .await
        .expect("exercise both adapters before invalid update");
    let before = parse_json_line(&before);
    assert_eq!(before["connect"], 200, "CONNECT before update: {before}");
    assert_eq!(before["forward"], 200, "forward before update: {before}");
    let history_before = run_cli(&["policy", "list", &guard.name])
        .await
        .expect("list policy history before rejected update");
    let connections_before_rejection = server.connection_count();

    let update_error = run_cli(&[
        "policy",
        "set",
        &guard.name,
        "--policy",
        &ambiguous_policy_path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await
    .expect_err("ambiguous policy must be rejected before persistence");
    assert!(
        update_error.contains("ambiguity validation failed"),
        "policy update should explain the ambiguity:\n{update_error}"
    );

    let history_after = run_cli(&["policy", "list", &guard.name])
        .await
        .expect("list policy history after rejected update");
    assert_eq!(
        history_after, history_before,
        "rejected policy must not create a revision"
    );

    let after_rejection = guard
        .exec(&["python3", "-c", &status_script])
        .await
        .expect("exercise both adapters after rejected update");
    let after_rejection = parse_json_line(&after_rejection);
    assert_eq!(
        after_rejection["connect"], 200,
        "CONNECT should keep using the active valid policy: {after_rejection}"
    );
    assert_eq!(
        after_rejection["forward"], 200,
        "forward HTTP should keep using the active valid policy: {after_rejection}"
    );
    assert!(
        server.connection_count() > connections_before_rejection,
        "active-policy requests should still contact the upstream server"
    );

    guard.cleanup().await;
}

#[tokio::test]
async fn destination_denial_modes_match_across_connect_and_forward_adapters() {
    let policy = write_destination_denial_policy().expect("write destination denial policy");
    let policy_path = policy_path(&policy);
    let script = r#"
import json
import os
import socket
import urllib.parse

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)

def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    headers, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    status = int(headers.split(None, 2)[1])
    return {"status": status, "body": json.loads(body.decode())}

def connect_result(host, port):
    with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
        target = f"{host}:{port}"
        sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        return read_response(sock)

def forward_result(host, port):
    with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
        target = f"{host}:{port}"
        sock.sendall(
            f"GET http://{target}/probe HTTP/1.1\r\n"
            f"Host: {target}\r\nConnection: close\r\n\r\n".encode()
        )
        return read_response(sock)

targets = {
    "metadata": ("169.254.169.254", 80),
    "loopback": ("127.0.0.1", 80),
    "control_plane": ("203.0.113.10", 6443),
    "outside_allowed_ips": ("203.0.113.10", 8080),
}
result = {}
for name, target in targets.items():
    result[name] = {
        "connect": connect_result(*target),
        "forward": forward_result(*target),
    }
print(json.dumps(result, sort_keys=True))
"#;

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", script])
        .await
        .expect("sandbox create");
    let result = parse_json_line(&guard.create_output);
    for name in [
        "metadata",
        "loopback",
        "control_plane",
        "outside_allowed_ips",
    ] {
        for adapter in ["connect", "forward"] {
            assert_eq!(
                result[name][adapter]["status"], 403,
                "{name} {adapter}: {result}"
            );
            assert_eq!(
                result[name][adapter]["body"]["error"], "ssrf_denied",
                "{name} {adapter}: {result}"
            );
        }
    }
    assert_eq!(
        result["metadata"]["connect"]["body"]["detail"],
        "CONNECT 169.254.169.254:80 blocked: declared endpoint check failed"
    );
    assert_eq!(
        result["metadata"]["forward"]["body"]["detail"],
        "GET 169.254.169.254:80 blocked: declared endpoint check failed"
    );
    assert_eq!(
        result["control_plane"]["connect"]["body"]["detail"],
        "CONNECT 203.0.113.10:6443 blocked: allowed_ips check failed"
    );
    assert_eq!(
        result["outside_allowed_ips"]["forward"]["body"]["detail"],
        "GET 203.0.113.10:8080 blocked: allowed_ips check failed"
    );
}

#[tokio::test]
async fn explicit_allowed_ips_and_implicit_ip_literals_succeed_through_both_adapters() {
    let resolver = SandboxGuard::create(&[
        "--",
        "python3",
        "-c",
        "import socket; print('GATEWAY_IP=' + socket.gethostbyname('host.openshell.internal'))",
    ])
    .await
    .expect("resolve host gateway inside sandbox");
    let gateway_ip = resolver
        .create_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("GATEWAY_IP="))
        .expect("sandbox gateway IPv4 output")
        .parse::<std::net::Ipv4Addr>()
        .expect("host gateway must resolve to IPv4 for this e2e");

    // Rootless Podman with pasta exposes its trusted host-gateway alias as a
    // link-local address. The hostname receives a narrow runtime exemption,
    // but the equivalent raw IP literal must remain hard-blocked. Other
    // drivers still exercise the successful IP-literal path below.
    if gateway_ip.is_loopback() || gateway_ip.is_link_local() || gateway_ip.is_unspecified() {
        eprintln!(
            "skipping IP-literal success assertions: host gateway {gateway_ip} is always blocked"
        );
        return;
    }

    let gateway_ip = gateway_ip.to_string();

    let explicit_server = KeepAliveHttpServer::start()
        .await
        .expect("start explicit allowed_ips server");
    let implicit_server = KeepAliveHttpServer::start()
        .await
        .expect("start implicit IP-literal server");
    let policy =
        write_ip_literal_success_policy(&gateway_ip, explicit_server.port, implicit_server.port)
            .expect("write IP literal policy");
    let policy_path = policy_path(&policy);
    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    for (mode, port) in [
        ("explicit_allowed_ips", explicit_server.port),
        ("implicit_ip_literal", implicit_server.port),
    ] {
        let output = guard
            .exec(&["python3", "-c", &proxy_status_script(&gateway_ip, port)])
            .await
            .unwrap_or_else(|error| panic!("exercise {mode}: {error}"));
        let statuses = parse_json_line(&output);
        assert_eq!(statuses["connect"], 200, "{mode} CONNECT: {statuses}");
        assert_eq!(statuses["forward"], 200, "{mode} forward: {statuses}");
    }

    guard.cleanup().await;
}

#[tokio::test]
async fn tls_skip_connect_relays_opaque_bytes_bidirectionally() {
    let server = EchoServer::start().await.expect("start TCP echo server");
    let policy = write_policy(TEST_SERVER_HOST, server.port, "        tls: skip")
        .expect("write tls: skip policy");
    let policy_path = policy_path(&policy);
    let script = format!(
        r#"
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}
PAYLOAD = bytes([0x00, 0xff, 0x13, 0x37, 0x80, 0x0a]) + b"not-http-or-tls" + bytes(range(64))

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)
with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
    target = f"{{HOST}}:{{PORT}}"
    sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if int(response.split(None, 2)[1]) != 200:
        raise RuntimeError("CONNECT was denied")
    sock.sendall(PAYLOAD)
    echoed = b""
    while len(echoed) < len(PAYLOAD):
        chunk = sock.recv(len(PAYLOAD) - len(echoed))
        if not chunk:
            break
        echoed += chunk
    if echoed != PAYLOAD:
        raise RuntimeError("opaque payload changed in transit")
print("RAW_RELAY_OK")
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");
    assert!(
        guard.create_output.contains("RAW_RELAY_OK"),
        "raw relay did not preserve the opaque payload:\n{}",
        guard.create_output
    );
}

#[tokio::test]
async fn middleware_redacts_request_bodies_through_both_adapters() {
    let server = RequestBodyEchoServer::start()
        .await
        .expect("start request body echo server");
    let policy = write_middleware_policy(TEST_SERVER_HOST, server.port, "", "fail_closed")
        .expect("write middleware policy");
    let policy_path = policy_path(&policy);
    let script = format!(
        r#"
import json
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}
SECRET = "sk-1234567890abcdef"

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)

def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("incomplete response headers")
        data += chunk
    headers, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    status = int(headers.split(None, 2)[1])
    if status != 200:
        raise RuntimeError(f"request failed with HTTP {{status}}: {{body!r}}")
    return json.loads(body[:length])

def request_bytes(target):
    body = json.dumps({{"api_key": SECRET}}, separators=(",", ":")).encode()
    return (
        f"POST {{target}} HTTP/1.1\r\n"
        f"Host: {{HOST}}:{{PORT}}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {{len(body)}}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body

target = f"{{HOST}}:{{PORT}}"
with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as forward_sock:
    forward_sock.sendall(request_bytes(f"http://{{target}}/middleware"))
    forward = read_response(forward_sock)

with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as connect_sock:
    connect_sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
    connect_response = b""
    while b"\r\n\r\n" not in connect_response:
        connect_response += connect_sock.recv(4096)
    if int(connect_response.split(None, 2)[1]) != 200:
        raise RuntimeError("CONNECT was denied")
    connect_sock.sendall(request_bytes("/middleware"))
    connect = read_response(connect_sock)

print(json.dumps({{"connect": connect, "forward": forward}}, sort_keys=True))
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");
    let result = parse_json_line(&guard.create_output);
    for adapter in ["connect", "forward"] {
        assert_eq!(
            result[adapter]["api_key"], "[REDACTED]",
            "{adapter} did not deliver the middleware-transformed body: {result}"
        );
    }
}

#[tokio::test]
async fn fail_closed_middleware_blocks_uninspectable_connect_payload_before_upstream() {
    let server = EchoServer::start().await.expect("start TCP echo server");
    let policy = write_middleware_policy(TEST_SERVER_HOST, server.port, "", "fail_closed")
        .expect("write fail-closed middleware policy");
    let policy_path = policy_path(&policy);
    let script = format!(
        r#"
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}
PAYLOAD = bytes([0x00, 0xff, 0x13, 0x37]) + b"not-http-or-tls"

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)
with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
    target = f"{{HOST}}:{{PORT}}"
    sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if int(response.split(None, 2)[1]) != 200:
        raise RuntimeError("CONNECT was denied before tunnel establishment")
    sock.sendall(PAYLOAD)
    denial = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except ConnectionResetError:
            break
        if not chunk:
            break
        denial += chunk
    if denial and (
        b"HTTP/1.1 403 Forbidden" not in denial
        or b"unsupported_l7_protocol" not in denial
    ):
        raise RuntimeError(f"missing fail-closed middleware denial: {{denial!r}}")
print("UNINSPECTABLE_MIDDLEWARE_BLOCKED")
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["sh", "-c", "echo Ready; sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");
    let output = guard
        .exec(&["python3", "-c", &script])
        .await
        .expect("exercise uninspectable fail-closed middleware");
    assert!(
        output.contains("UNINSPECTABLE_MIDDLEWARE_BLOCKED"),
        "uninspectable payload was not blocked:\n{output}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        server.observed_bytes().is_empty(),
        "uninspectable payload reached upstream before middleware denial"
    );

    let logs = wait_for_sandbox_logs(&guard.name, |logs| {
        logs.contains("openshell.middleware.traffic_uninspectable")
            && logs
                .contains("Unsupported tunnel protocol cannot be inspected by required middleware")
    })
    .await
    .expect("fetch sandbox logs after middleware denial");
    assert!(
        logs.contains("openshell.middleware.traffic_uninspectable")
            && logs
                .contains("Unsupported tunnel protocol cannot be inspected by required middleware"),
        "OCSF logs should explain the fail-closed denial:\n{logs}"
    );

    guard.cleanup().await;
}

#[tokio::test]
async fn fail_open_middleware_bypasses_uninspectable_tls_skip_connect() {
    let server = EchoServer::start().await.expect("start TCP echo server");
    let policy = write_middleware_policy(
        TEST_SERVER_HOST,
        server.port,
        "        tls: skip",
        "fail_open",
    )
    .expect("write fail-open middleware policy");
    let policy_path = policy_path(&policy);
    let script = format!(
        r#"
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}
PAYLOAD = bytes([0x00, 0xff, 0x13, 0x37, 0x80]) + b"middleware-bypass"

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)
with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
    target = f"{{HOST}}:{{PORT}}"
    sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        response += sock.recv(4096)
    if int(response.split(None, 2)[1]) != 200:
        raise RuntimeError("CONNECT was denied")
    sock.sendall(PAYLOAD)
    echoed = b""
    while len(echoed) < len(PAYLOAD):
        chunk = sock.recv(len(PAYLOAD) - len(echoed))
        if not chunk:
            break
        echoed += chunk
    if echoed != PAYLOAD:
        raise RuntimeError(f"fail-open middleware did not preserve raw relay: {{echoed!r}}")
print("UNINSPECTABLE_MIDDLEWARE_BYPASSED")
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");
    assert!(
        guard
            .create_output
            .contains("UNINSPECTABLE_MIDDLEWARE_BYPASSED"),
        "fail-open middleware did not bypass uninspectable traffic:\n{}",
        guard.create_output
    );
    assert_eq!(
        server.observed_bytes(),
        [0x00, 0xff, 0x13, 0x37, 0x80]
            .into_iter()
            .chain(*b"middleware-bypass")
            .collect::<Vec<_>>(),
        "upstream did not receive the unchanged fail-open payload"
    );
}

#[tokio::test]
async fn forward_pipeline_never_reaches_upstream_as_first_request_overflow() {
    let server = PipelineProbeServer::start()
        .await
        .expect("start pipeline probe server");
    let endpoint_options = r#"        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: "/allowed""#;
    let policy = write_policy(TEST_SERVER_HOST, server.port, endpoint_options)
        .expect("write pipeline policy");
    let policy_path = policy_path(&policy);
    let script = format!(
        r#"
import os
import socket
import urllib.parse

proxy_url = next(
    os.environ[name]
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
    if os.environ.get(name)
)
parsed = urllib.parse.urlparse(proxy_url)
target = "{host}:{port}"
first = (
    f"GET http://{{target}}/allowed HTTP/1.1\r\n"
    f"Host: {{target}}\r\nConnection: keep-alive\r\n\r\n"
)
second = (
    f"POST http://{{target}}/blocked HTTP/1.1\r\n"
    f"Host: {{target}}\r\nContent-Length: 0\r\n\r\n"
)
with socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10) as sock:
    sock.sendall((first + second).encode())
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
if response.count(b"HTTP/1.1 ") != 1 or b" 200 " not in response.split(b"\r\n", 1)[0]:
    raise RuntimeError(f"unexpected pipelined response: {{response!r}}")
print("FORWARD_PIPELINE_CLOSED")
"#,
        host = TEST_SERVER_HOST,
        port = server.port,
    );

    let guard = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("sandbox create");
    assert!(
        guard.create_output.contains("FORWARD_PIPELINE_CLOSED"),
        "forward proxy did not close after one response:\n{}",
        guard.create_output
    );

    let observed = String::from_utf8(server.observed_request()).expect("upstream HTTP request");
    assert!(observed.starts_with("GET /allowed HTTP/1.1\r\n"));
    assert!(
        !observed.to_ascii_lowercase().contains("\r\nconnection:"),
        "shared relay must remove hop-by-hop connection headers:\n{observed}"
    );
    assert!(!observed.contains("/blocked"));
}

#[tokio::test]
async fn http_credentials_are_rewritten_in_headers_and_bodies_for_both_adapters() {
    let _provider_lock = PROVIDER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    delete_provider(PROVIDER_NAME).await;
    create_generic_provider(PROVIDER_NAME)
        .await
        .expect("create generic provider");

    let result = async {
        let server = CredentialProbeServer::start().await?;
        let endpoint_options = r#"        protocol: rest
        enforcement: enforce
        request_body_credential_rewrite: true
        rules:
          - allow:
              method: POST
              path: "/probe""#;
        let policy = write_policy(TEST_SERVER_HOST, server.port, endpoint_options)?;
        let policy_path = policy_path(&policy);
        let script = format!(
            r#"
import json
import os
import socket
import urllib.parse

HOST = {host:?}
PORT = {port}
TOKEN = os.environ[{token_env:?}]

def proxy_parts():
    proxy_url = next(
        os.environ[name]
        for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy")
        if os.environ.get(name)
    )
    parsed = urllib.parse.urlparse(proxy_url)
    return parsed.hostname, parsed.port or 80

def read_response(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("incomplete response headers")
        data += chunk
    headers, body = data.split(b"\r\n\r\n", 1)
    length = 0
    for line in headers.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk
    code = int(headers.split(None, 2)[1])
    if code != 200:
        raise RuntimeError(f"request failed with HTTP {{code}}")
    return json.loads(body[:length])

def request_bytes(target):
    body = json.dumps({{"credential": TOKEN}}, separators=(",", ":")).encode()
    return (
        f"POST {{target}} HTTP/1.1\r\n"
        f"Host: {{HOST}}:{{PORT}}\r\n"
        f"Authorization: Bearer {{TOKEN}}\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {{len(body)}}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + body

proxy_host, proxy_port = proxy_parts()
target = f"{{HOST}}:{{PORT}}"
with socket.create_connection((proxy_host, proxy_port), timeout=10) as forward_sock:
    forward_sock.sendall(request_bytes(f"http://{{target}}/probe"))
    forward = read_response(forward_sock)

with socket.create_connection((proxy_host, proxy_port), timeout=10) as connect_sock:
    connect_sock.sendall(f"CONNECT {{target}} HTTP/1.1\r\nHost: {{target}}\r\n\r\n".encode())
    connect_response = b""
    while b"\r\n\r\n" not in connect_response:
        connect_response += connect_sock.recv(4096)
    if int(connect_response.split(None, 2)[1]) != 200:
        raise RuntimeError("CONNECT was denied")
    connect_sock.sendall(request_bytes("/probe"))
    connect = read_response(connect_sock)

print(json.dumps({{"connect": connect, "forward": forward}}, sort_keys=True))
"#,
            host = TEST_SERVER_HOST,
            port = server.port,
            token_env = TOKEN_ENV,
        );

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
    let result = parse_json_line(&guard.create_output);
    for adapter in ["connect", "forward"] {
        assert_eq!(
            result[adapter]["header_resolved"], true,
            "{adapter} header placeholder was not resolved: {result}"
        );
        assert_eq!(
            result[adapter]["body_resolved"], true,
            "{adapter} body placeholder was not resolved: {result}"
        );
        assert_eq!(
            result[adapter]["saw_placeholder"], false,
            "{adapter} leaked an unresolved placeholder upstream: {result}"
        );
    }
    assert!(
        !guard.create_output.contains(TEST_SECRET),
        "sandbox output exposed the raw provider credential:\n{}",
        guard.create_output
    );
    assert!(
        !guard.create_output.contains(PLACEHOLDER_PREFIX),
        "sandbox output exposed an unresolved provider placeholder:\n{}",
        guard.create_output
    );
}
