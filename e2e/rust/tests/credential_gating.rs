// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E coverage for credentialed endpoint admission and REST body backstops.
//!
//! Each test installs its own provider and profile under a unique name, so the
//! tests can run in parallel. Each test prints its steps to stderr with the
//! elapsed time, so a timeout shows which step was slow.

use std::fmt::Display;
use std::io::Write;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::sandbox::SandboxGuard;
use sha1::{Digest, Sha1};
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const TEST_HOST: &str = "host.openshell.internal";
const TOKEN_ENV: &str = "E2E_GATING_TOKEN";
const TEST_SECRET: &str = "e2e-gating-secret-value";
const PLACEHOLDER_PREFIX: &str = "openshell:resolve:env:";
const KEY_PRESENCE_SCRIPT: &str = r#"if [ "${E2E_GATING_TOKEN+x}" != x ]; then
  echo TOKEN_ABSENT
else
  case "$E2E_GATING_TOKEN" in
    openshell:resolve:env:*) echo TOKEN_PLACEHOLDER ;;
    *) echo TOKEN_UNSAFE ;;
  esac
fi"#;
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

async fn run_cli(args: &[&str]) -> (bool, String) {
    let mut command = openshell_cmd();
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command.output().await.expect("spawn openshell CLI");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// Prints a test's steps to stderr with the time since the test started.
#[derive(Clone, Copy)]
struct Progress {
    scenario: &'static str,
    started: Instant,
}

impl Progress {
    fn start(scenario: &'static str) -> Self {
        let progress = Self {
            scenario,
            started: Instant::now(),
        };
        progress.step("start");
        progress
    }

    fn step(self, message: impl Display) {
        eprintln!(
            "credential_gating[{}] +{:.1}s {message}",
            self.scenario,
            self.started.elapsed().as_secs_f64()
        );
    }
}

fn utf8_path(file: &NamedTempFile) -> Result<&str, String> {
    file.path()
        .to_str()
        .ok_or_else(|| format!("{} is not UTF-8", file.path().display()))
}

/// Retry a delete until it takes effect.
///
/// The gateway refuses to delete a provider or a profile that a sandbox still
/// references, and sandbox teardown drains asynchronously, so a single attempt
/// can be rejected right after a sandbox was removed. This runs from `Drop`,
/// so it blocks instead of awaiting.
fn delete_until_gone(args: &[&str]) -> Result<(), String> {
    const ATTEMPTS: u32 = 40;
    let binary = openshell_bin();
    let mut last_output = String::new();
    for _ in 0..ATTEMPTS {
        match std::process::Command::new(&binary)
            .args(args)
            .stdin(Stdio::null())
            .output()
        {
            Ok(output) => {
                let combined = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if output.status.success() || combined.to_lowercase().contains("not found") {
                    return Ok(());
                }
                last_output = combined;
            }
            Err(error) => last_output = format!("spawn openshell CLI: {error}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(format!(
        "'{}' still failing after {ATTEMPTS} attempts:\n{last_output}",
        args.join(" ")
    ))
}

/// A provider and the profile it uses, both under one name unique to the
/// test. Dropping it deletes both, also when the test fails.
struct GatingProvider {
    name: String,
    progress: Progress,
}

impl GatingProvider {
    async fn install_with_endpoints(
        progress: Progress,
        rest_port: u16,
        websocket_port: u16,
    ) -> Result<Self, String> {
        let name = unique_name(progress.scenario);
        let profile = write_provider_profile(&name, rest_port, websocket_port)?;
        Self::install(progress, name, &profile).await
    }

    async fn install_endpointless(progress: Progress) -> Result<Self, String> {
        let name = unique_name(progress.scenario);
        let profile = write_endpointless_provider_profile(&name)?;
        Self::install(progress, name, &profile).await
    }

    async fn install(
        progress: Progress,
        name: String,
        profile: &NamedTempFile,
    ) -> Result<Self, String> {
        progress.step(format_args!("importing profile {name}"));
        let (imported, output) =
            run_cli(&["profile", "import", "--file", utf8_path(profile)?]).await;
        if !imported {
            return Err(format!("profile import failed:\n{output}"));
        }
        let provider = Self { name, progress };
        progress.step(format_args!("creating provider {}", provider.name));
        let credential = format!("{TOKEN_ENV}={TEST_SECRET}");
        let (created, output) = run_cli(&[
            "provider",
            "create",
            "--name",
            &provider.name,
            "--type",
            &provider.name,
            "--credential",
            &credential,
        ])
        .await;
        if !created {
            return Err(format!("provider create failed:\n{output}"));
        }
        Ok(provider)
    }
}

impl Drop for GatingProvider {
    fn drop(&mut self) {
        self.progress
            .step(format_args!("deleting provider and profile {}", self.name));
        for kind in ["provider", "profile"] {
            if let Err(error) = delete_until_gone(&[kind, "delete", &self.name]) {
                self.progress
                    .step(format_args!("{kind} cleanup did not settle: {error}"));
            }
        }
        self.progress.step("cleanup finished");
    }
}

/// A provider and profile name that does not collide with parallel tests or
/// earlier runs against the same gateway.
fn unique_name(scenario: &str) -> String {
    format!(
        "e2e-cg-{scenario}-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    )
}

fn write_provider_profile(
    profile_id: &str,
    rest_port: u16,
    websocket_port: u16,
) -> Result<NamedTempFile, String> {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create profile: {error}"))?;
    let profile = format!(
        r"id: {profile_id}
display_name: E2E Credential Gating
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: {TEST_HOST}
    port: {rest_port}
    protocol: rest
    access: full
  - host: {TEST_HOST}
    port: {websocket_port}
    protocol: websocket
    access: read-write
binaries:
  - path: /usr/bin/python*
  - path: /usr/local/bin/python*
  - path: /sandbox/.uv/python/*/bin/python*
",
    );
    file.write_all(profile.as_bytes())
        .map_err(|error| format!("write profile: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush profile: {error}"))?;
    Ok(file)
}

fn write_endpointless_provider_profile(profile_id: &str) -> Result<NamedTempFile, String> {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .map_err(|error| format!("create endpointless profile: {error}"))?;
    let profile = format!(
        r"id: {profile_id}
display_name: E2E Endpointless Credential Gating
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
binaries:
  - path: /usr/bin/python*
  - path: /usr/local/bin/python*
  - path: /sandbox/.uv/python/*/bin/python*
",
    );
    file.write_all(profile.as_bytes())
        .map_err(|error| format!("write endpointless profile: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush endpointless profile: {error}"))?;
    Ok(file)
}

#[derive(Clone, Copy)]
enum EndpointMode {
    L4,
    TlsSkip,
    L4OptIn,
    RestBody { rewrite: bool },
    WebSocket,
}

#[derive(Clone, Copy)]
enum CredentialSource {
    ProviderProfile,
    PolicyBinding,
}

fn write_policy(
    port: u16,
    mode: EndpointMode,
    credential_source: CredentialSource,
    provider: &str,
) -> Result<NamedTempFile, String> {
    let mut file = NamedTempFile::new().map_err(|error| format!("create policy: {error}"))?;
    let endpoint_options = match mode {
        EndpointMode::L4 => String::new(),
        EndpointMode::TlsSkip => {
            "        protocol: rest\n        access: full\n        tls: skip\n".to_string()
        }
        EndpointMode::L4OptIn => "        allow_uninspected_credentials: true\n".to_string(),
        EndpointMode::RestBody { rewrite } => format!(
            "        protocol: rest\n        access: full\n        request_body_credential_rewrite: {rewrite}\n"
        ),
        EndpointMode::WebSocket => {
            "        protocol: websocket\n        access: read-write\n".to_string()
        }
    };
    let credential_binding = match credential_source {
        CredentialSource::ProviderProfile => String::new(),
        CredentialSource::PolicyBinding => {
            format!("        credential_binding:\n          provider: {provider}\n")
        }
    };
    let policy = format!(
        r"version: 1
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
  credential_gating:
    name: credential_gating
    endpoints:
      - host: {TEST_HOST}
        port: {port}
{endpoint_options}{credential_binding}    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
",
    );
    file.write_all(policy.as_bytes())
        .map_err(|error| format!("write policy: {error}"))?;
    file.flush()
        .map_err(|error| format!("flush policy: {error}"))?;
    Ok(file)
}

#[derive(Debug, Default, Clone, Copy)]
struct BodyObservation {
    saw_placeholder: bool,
    saw_secret: bool,
}

struct HttpProbeServer {
    port: u16,
    observations: Arc<Mutex<Vec<BodyObservation>>>,
    task: JoinHandle<()>,
}

impl HttpProbeServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind HTTP probe: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read HTTP probe address: {error}"))?
            .port();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let task_observations = Arc::clone(&observations);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let observations = Arc::clone(&task_observations);
                tokio::spawn(async move {
                    let _ = handle_http_probe(stream, observations).await;
                });
            }
        });
        Ok(Self {
            port,
            observations,
            task,
        })
    }

    async fn wait_for_observations(&self, count: usize) -> Vec<BodyObservation> {
        for _ in 0..100 {
            let observations = self.observations.lock().unwrap().clone();
            if observations.len() >= count {
                return observations;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        self.observations.lock().unwrap().clone()
    }
}

impl Drop for HttpProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct BinaryWebSocketProbeServer {
    port: u16,
    handshake_seen: Arc<AtomicBool>,
    binary_seen: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl BinaryWebSocketProbeServer {
    async fn start() -> Result<Self, String> {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .map_err(|error| format!("bind WebSocket probe: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("read WebSocket probe address: {error}"))?
            .port();
        let handshake_seen = Arc::new(AtomicBool::new(false));
        let binary_seen = Arc::new(AtomicBool::new(false));
        let task_handshake_seen = Arc::clone(&handshake_seen);
        let task_binary_seen = Arc::clone(&binary_seen);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let handshake_seen = Arc::clone(&task_handshake_seen);
                let binary_seen = Arc::clone(&task_binary_seen);
                tokio::spawn(async move {
                    let _ =
                        handle_binary_websocket_probe(stream, handshake_seen, binary_seen).await;
                });
            }
        });
        Ok(Self {
            port,
            handshake_seen,
            binary_seen,
            task,
        })
    }

    async fn wait_for_handshake(&self) -> bool {
        for _ in 0..100 {
            if self.handshake_seen.load(Ordering::Acquire) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }
}

impl Drop for BinaryWebSocketProbeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn recv_until(stream: &mut TcpStream, marker: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Ok(received);
        }
        received.extend_from_slice(&buffer[..read]);
        if received
            .windows(marker.len())
            .any(|window| window == marker)
        {
            return Ok(received);
        }
    }
}

fn websocket_header_value(request: &str, name: &str) -> Option<String> {
    request.lines().find_map(|line| {
        let (header, value) = line.split_once(':')?;
        header
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| value.trim().to_string())
    })
}

fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

async fn handle_binary_websocket_probe(
    mut stream: TcpStream,
    handshake_seen: Arc<AtomicBool>,
    binary_seen: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let request_bytes = recv_until(&mut stream, b"\r\n\r\n").await?;
    let request = String::from_utf8_lossy(&request_bytes);
    let key = websocket_header_value(&request, "Sec-WebSocket-Key").ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing WebSocket key")
    })?;
    let accept = websocket_accept(&key);
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\
         \r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    handshake_seen.store(true, Ordering::Release);

    let mut header = [0_u8; 2];
    if tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
        .await
        .is_ok_and(|result| result.is_ok())
        && header[0] & 0x0f == 0x02
    {
        binary_seen.store(true, Ordering::Release);
    }
    Ok(())
}

async fn handle_http_probe(
    mut stream: TcpStream,
    observations: Arc<Mutex<Vec<BodyObservation>>>,
) -> std::io::Result<()> {
    let mut received = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut expected_total = None;
    loop {
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buffer)).await;
        let Ok(Ok(read)) = read else {
            break;
        };
        if read == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..read]);
        if expected_total.is_none()
            && let Some(header_end) = received.windows(4).position(|window| window == b"\r\n\r\n")
        {
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&received[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            expected_total = Some(header_end + content_length);
        }
        if expected_total.is_some_and(|expected| received.len() >= expected) {
            break;
        }
    }

    let observation = BodyObservation {
        saw_placeholder: received
            .windows(PLACEHOLDER_PREFIX.len())
            .any(|window| window == PLACEHOLDER_PREFIX.as_bytes()),
        saw_secret: received
            .windows(TEST_SECRET.len())
            .any(|window| window == TEST_SECRET.as_bytes()),
    };
    observations.lock().unwrap().push(observation);
    if expected_total.is_some_and(|expected| received.len() >= expected) {
        let result = if observation.saw_secret && !observation.saw_placeholder {
            "BODY_REWRITTEN"
        } else if observation.saw_placeholder && !observation.saw_secret {
            "BODY_TEXT"
        } else {
            "BODY_BAD"
        };
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}",
            result.len()
        );
        stream.write_all(response.as_bytes()).await?;
    }
    Ok(())
}

fn body_client_script(port: u16) -> String {
    format!(
        r#"
import os
import socket

host = {TEST_HOST:?}
port = {port}
token = os.environ[{TOKEN_ENV:?}]

with socket.create_connection((host, port), timeout=10) as sock:
    target = f"{{host}}:{{port}}"
    body = ("prefix-" + token + "-suffix").encode("utf-8")
    request = (
        f"POST /token HTTP/1.1\r\nHost: {{target}}\r\n"
        f"Content-Type: text/plain\r\nContent-Length: {{len(body)}}\r\nConnection: close\r\n\r\n"
    ).encode("ascii") + body
    sock.sendall(request)
    sock.settimeout(3)
    response = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        response += chunk
    print("BODY_REWRITTEN" if b"BODY_REWRITTEN" in response else "BODY_TEXT" if b"BODY_TEXT" in response else "BODY_DENIED")
"#
    )
}

fn binary_websocket_client_script(port: u16) -> String {
    format!(
        r#"
import base64
import os
import socket
import struct

host = {TEST_HOST:?}
port = {port}

def recv_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            break
        data += chunk
    return data

with socket.create_connection((host, port), timeout=10) as sock:
    target = f"{{host}}:{{port}}"
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    request = (
        f"GET /ws HTTP/1.1\r\nHost: {{target}}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {{key}}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(request.encode("ascii"))
    if not recv_until(sock, b"\r\n\r\n").startswith(b"HTTP/1.1 101"):
        raise RuntimeError("upgrade failed")
    payload = b"binary-credential-channel"
    mask = os.urandom(4)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    frame = bytes([0x82, 0x80 | len(payload)]) + mask + masked
    sock.sendall(frame)
    sock.settimeout(3)
    denied = False
    try:
        header = recv_exact(sock, 2)
        if not header:
            denied = True
        elif len(header) == 2:
            opcode = header[0] & 0x0f
            masked = bool(header[1] & 0x80)
            payload_length = header[1] & 0x7f
            if opcode == 0x08 and not masked and payload_length < 126:
                close_payload = recv_exact(sock, payload_length)
                denied = (
                    len(close_payload) >= 2
                    and struct.unpack("!H", close_payload[:2])[0] == 1008
                )
    except socket.timeout:
        denied = True
    print("BINARY_DENIED" if denied else "BINARY_FORWARDED")
"#
    )
}

async fn sandbox_create_failure(
    progress: Progress,
    label: &str,
    provider: &str,
    policy: &NamedTempFile,
) -> String {
    progress.step(format_args!(
        "{label}: creating sandbox, expecting rejection"
    ));
    let policy_path = policy.path().to_str().expect("policy path is UTF-8");
    let (success, output) = run_cli(&[
        "sandbox",
        "create",
        "--policy",
        policy_path,
        "--provider",
        provider,
        "--",
        "echo",
        "must-not-run",
    ])
    .await;
    assert!(!success, "sandbox create unexpectedly succeeded:\n{output}");
    progress.step(format_args!("{label}: rejected"));
    output
}

/// Create a sandbox, run one command in it, and delete it.
///
/// Returns the create output followed by the command output.
async fn run_in_sandbox(
    progress: Progress,
    label: &str,
    create_args: &[&str],
    command: &[&str],
) -> Result<String, String> {
    progress.step(format_args!("{label}: creating sandbox"));
    let mut sandbox = SandboxGuard::create(create_args).await?;
    progress.step(format_args!(
        "{label}: sandbox {} ready, running command",
        sandbox.name
    ));
    let output = sandbox.exec(command).await;
    progress.step(format_args!("{label}: deleting sandbox {}", sandbox.name));
    sandbox.cleanup().await;
    progress.step(format_args!("{label}: sandbox deleted"));
    Ok(format!("{}{}", sandbox.create_output, output?))
}

async fn assert_gateway_admission(
    progress: Progress,
    provider: &str,
    port: u16,
    credential_source: CredentialSource,
) -> Result<(), String> {
    let l4 = write_policy(port, EndpointMode::L4, credential_source, provider)?;
    let l4_error = sandbox_create_failure(progress, "L4-only policy", provider, &l4).await;
    assert!(l4_error.contains("credentialed endpoint"), "{l4_error}");
    assert!(l4_error.contains("L4-only"), "{l4_error}");

    let tls_skip = write_policy(port, EndpointMode::TlsSkip, credential_source, provider)?;
    let tls_error = sandbox_create_failure(progress, "tls: skip policy", provider, &tls_skip).await;
    assert!(tls_error.contains("credentialed endpoint"), "{tls_error}");
    assert!(
        tls_error.contains("tls:") && tls_error.contains("skip"),
        "{tls_error}"
    );

    let opt_in = write_policy(port, EndpointMode::L4OptIn, credential_source, provider)?;
    let accepted_marker = match credential_source {
        CredentialSource::ProviderProfile => "OPT_IN_ACCEPTED",
        CredentialSource::PolicyBinding => "ENDPOINTLESS_OPT_IN_ACCEPTED",
    };
    let output = run_in_sandbox(
        progress,
        "opt-in policy",
        &["--policy", utf8_path(&opt_in)?, "--provider", provider],
        &["echo", accepted_marker],
    )
    .await?;
    assert!(output.contains(accepted_marker), "{output}");
    Ok(())
}

async fn wait_for_provider_key_presence(
    sandbox: &SandboxGuard,
    expected_present: bool,
) -> Result<(), String> {
    let expected = if expected_present {
        "TOKEN_PLACEHOLDER"
    } else {
        "TOKEN_ABSENT"
    };
    let mut last_output = String::new();
    for _ in 0..60 {
        last_output = sandbox.exec(&["sh", "-lc", KEY_PRESENCE_SCRIPT]).await?;
        if last_output.contains(expected) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Err(format!(
        "provider environment did not converge to {expected}; last key-presence output:\n{last_output}"
    ))
}

async fn set_policy(progress: Progress, sandbox: &str, policy_path: &str) -> Result<(), String> {
    let (success, output) = run_cli(&[
        "policy",
        "set",
        sandbox,
        "--policy",
        policy_path,
        "--wait",
        "--timeout",
        "120",
    ])
    .await;
    if !success {
        return Err(format!("policy update failed:\n{output}"));
    }
    progress.step("policy applied");
    Ok(())
}

async fn assert_endpointless_provider_env_live_update(
    progress: Progress,
    provider: &str,
    port: u16,
) -> Result<(), String> {
    let unbound = write_policy(
        port,
        EndpointMode::RestBody { rewrite: false },
        CredentialSource::ProviderProfile,
        provider,
    )?;
    let bound = write_policy(
        port,
        EndpointMode::RestBody { rewrite: false },
        CredentialSource::PolicyBinding,
        provider,
    )?;
    let unbound_path = utf8_path(&unbound)?;
    let bound_path = utf8_path(&bound)?;

    progress.step("creating long-running sandbox with the unbound policy");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", unbound_path, "--provider", provider, "--no-tty"],
        &["sh", "-c", "echo PROVIDER_UPDATE_READY && sleep infinity"],
        "PROVIDER_UPDATE_READY",
    )
    .await?;

    let result = async {
        progress.step(format_args!(
            "sandbox {} ready, waiting for the token to be absent",
            sandbox.name
        ));
        wait_for_provider_key_presence(&sandbox, false).await?;

        progress.step("binding the provider with policy set --wait");
        set_policy(progress, &sandbox.name, bound_path)
            .await
            .map_err(|error| format!("binding {error}"))?;
        progress.step("waiting for the token placeholder");
        wait_for_provider_key_presence(&sandbox, true).await?;

        progress.step("unbinding the provider with policy set --wait");
        set_policy(progress, &sandbox.name, unbound_path)
            .await
            .map_err(|error| format!("unbinding {error}"))?;
        progress.step("waiting for the token to be absent");
        wait_for_provider_key_presence(&sandbox, false).await
    }
    .await;

    progress.step(format_args!("deleting sandbox {}", sandbox.name));
    sandbox.cleanup().await;
    progress.step("sandbox deleted");
    result
}

async fn run_body_sandbox(
    progress: Progress,
    provider: &str,
    port: u16,
    mode: EndpointMode,
    credential_source: CredentialSource,
) -> Result<String, String> {
    let policy = write_policy(port, mode, credential_source, provider)?;
    let script = body_client_script(port);
    run_in_sandbox(
        progress,
        "REST body client",
        &["--policy", utf8_path(&policy)?, "--provider", provider],
        &["python3", "-c", &script],
    )
    .await
}

async fn assert_websocket_binary_denied(
    progress: Progress,
    provider: &str,
    server: &BinaryWebSocketProbeServer,
) -> Result<(), String> {
    let policy = write_policy(
        server.port,
        EndpointMode::WebSocket,
        CredentialSource::ProviderProfile,
        provider,
    )?;
    let script = binary_websocket_client_script(server.port);
    let output = run_in_sandbox(
        progress,
        "WebSocket client",
        &["--policy", utf8_path(&policy)?, "--provider", provider],
        &["python3", "-c", &script],
    )
    .await?;
    assert!(output.contains("BINARY_DENIED"), "{output}");
    assert!(
        server.wait_for_handshake().await,
        "upstream should receive the WebSocket handshake"
    );
    assert!(
        !server.binary_seen.load(Ordering::Acquire),
        "credentialed WebSocket binary frame reached upstream"
    );
    Ok(())
}

/// Start both probe servers and install a provider whose profile declares
/// their endpoints.
async fn profile_endpoint_fixture(
    progress: Progress,
) -> (HttpProbeServer, BinaryWebSocketProbeServer, GatingProvider) {
    let server = HttpProbeServer::start().await.expect("start HTTP probe");
    let websocket_server = BinaryWebSocketProbeServer::start()
        .await
        .expect("start WebSocket probe");
    let provider =
        GatingProvider::install_with_endpoints(progress, server.port, websocket_server.port)
            .await
            .expect("install credentialed provider");
    (server, websocket_server, provider)
}

/// Start the HTTP probe server and install a provider whose profile declares
/// no endpoints, so policies must bind it explicitly.
async fn endpointless_fixture(progress: Progress) -> (HttpProbeServer, GatingProvider) {
    let server = HttpProbeServer::start().await.expect("start HTTP probe");
    let provider = GatingProvider::install_endpointless(progress)
        .await
        .expect("install endpointless provider");
    (server, provider)
}

#[tokio::test]
async fn profile_rest_endpoint_keeps_body_placeholder() {
    let progress = Progress::start("profile-rest");
    let (server, _websocket_server, provider) = profile_endpoint_fixture(progress).await;

    let output = run_body_sandbox(
        progress,
        &provider.name,
        server.port,
        EndpointMode::RestBody { rewrite: false },
        CredentialSource::ProviderProfile,
    )
    .await
    .expect("run REST body client");
    assert!(output.contains("BODY_TEXT"), "{output}");
    let observations = server.wait_for_observations(1).await;
    assert_eq!(observations.len(), 1, "observations: {observations:?}");
    assert!(observations[0].saw_placeholder);
    assert!(!observations[0].saw_secret);
    progress.step("checks passed");
}

#[tokio::test]
async fn profile_websocket_endpoint_denies_binary_frames() {
    let progress = Progress::start("profile-websocket");
    let (_server, websocket_server, provider) = profile_endpoint_fixture(progress).await;

    assert_websocket_binary_denied(progress, &provider.name, &websocket_server)
        .await
        .expect("run WebSocket client");
    progress.step("checks passed");
}

#[tokio::test]
async fn policy_binding_requires_inspection_or_opt_in() {
    let progress = Progress::start("binding-admission");
    let (server, provider) = endpointless_fixture(progress).await;

    assert_gateway_admission(
        progress,
        &provider.name,
        server.port,
        CredentialSource::PolicyBinding,
    )
    .await
    .expect("gateway admission");
    progress.step("checks passed");
}

#[tokio::test]
async fn policy_binding_rest_body_keeps_placeholder_without_rewrite() {
    let progress = Progress::start("binding-body");
    let (server, provider) = endpointless_fixture(progress).await;

    let literal = run_body_sandbox(
        progress,
        &provider.name,
        server.port,
        EndpointMode::RestBody { rewrite: false },
        CredentialSource::PolicyBinding,
    )
    .await
    .expect("run REST body client");
    assert!(literal.contains("BODY_TEXT"), "{literal}");
    let observations = server.wait_for_observations(1).await;
    assert_eq!(observations.len(), 1, "observations: {observations:?}");
    assert!(observations[0].saw_placeholder);
    assert!(!observations[0].saw_secret);
    progress.step("checks passed");
}

#[tokio::test]
async fn policy_binding_rest_body_rewrite_sends_secret_upstream() {
    let progress = Progress::start("binding-rewrite");
    let (server, provider) = endpointless_fixture(progress).await;

    let rewritten = run_body_sandbox(
        progress,
        &provider.name,
        server.port,
        EndpointMode::RestBody { rewrite: true },
        CredentialSource::PolicyBinding,
    )
    .await
    .expect("run REST body client");
    assert!(rewritten.contains("BODY_REWRITTEN"));
    assert!(!rewritten.contains(TEST_SECRET));
    assert!(!rewritten.contains(PLACEHOLDER_PREFIX));
    let observations = server.wait_for_observations(1).await;
    assert_eq!(observations.len(), 1, "observations: {observations:?}");
    assert!(!observations[0].saw_placeholder);
    assert!(observations[0].saw_secret);
    progress.step("checks passed");
}

#[tokio::test]
async fn policy_binding_updates_provider_environment_live() {
    let progress = Progress::start("binding-live-update");
    let (server, provider) = endpointless_fixture(progress).await;

    assert_endpointless_provider_env_live_update(progress, &provider.name, server.port)
        .await
        .expect("provider environment live update");
    progress.step("checks passed");
}
