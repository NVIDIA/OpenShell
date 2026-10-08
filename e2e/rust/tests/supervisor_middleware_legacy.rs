// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Released-binary compatibility for the legacy supervisor middleware protocol.
//!
//! Runs the `supervisor-middleware-content-guard` example built from the
//! `v0.1.2` tag as an operator-registered middleware service for the current
//! gateway and Docker sandbox supervisor. `mise run e2e:middleware-legacy`
//! builds that binary and exports `OPENSHELL_E2E_LEGACY_CONTENT_GUARD_BIN`;
//! without it the test skips, unless
//! `OPENSHELL_E2E_REQUIRE_LEGACY_MIDDLEWARE=1` makes the binary mandatory.
//!
//! The test registers the service in the managed gateway config, restarts the
//! gateway (which describes it), and checks with sandboxes that:
//! - redact mode rewrites request and response bodies;
//! - deny mode returns the canonical 403 with the service's reason code;
//! - a body the service rejects fails closed (403 request, 502 response) under
//!   `fail_closed` and passes unchanged under `fail_open`;
//! - a `fail_open` attachment may select a `tls: skip` endpoint, which is
//!   relayed raw.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_healthy;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use serial_test::serial;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

const BIN_ENV: &str = "OPENSHELL_E2E_LEGACY_CONTENT_GUARD_BIN";
const REQUIRE_ENV: &str = "OPENSHELL_E2E_REQUIRE_LEGACY_MIDDLEWARE";
/// Operator registration name used by the example policy.
const REGISTRATION: &str = "content-guard-example";
const SANDBOX_HOST: &str = "host.openshell.internal";
const SENSITIVE_BODY: &str = "contains prototype-secret and internal-only";
const CLEAN_BODY: &str = "ordinary public text";
const BINARY_BODY: &[u8] = b"\xff\xfeprototype-secret";
const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;

/// The legacy content guard, run as a host process.
struct LegacyContentGuard {
    child: tokio::process::Child,
    port: u16,
}

impl LegacyContentGuard {
    async fn start(binary: &str) -> Self {
        let port = find_free_port();
        let child = tokio::process::Command::new(binary)
            .arg("--bind")
            .arg(format!("0.0.0.0:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|error| panic!("start legacy content guard '{binary}': {error}"));
        wait_for_port("127.0.0.1", port, Duration::from_secs(30))
            .await
            .expect("legacy content guard listens");
        Self { child, port }
    }
}

impl Drop for LegacyContentGuard {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Appends the content-guard registration to the managed gateway config,
/// restarts the gateway, and restores both on drop.
struct GatewayRegistration {
    config_path: PathBuf,
    original: Vec<u8>,
}

impl GatewayRegistration {
    fn config_path() -> PathBuf {
        let args_file = std::env::var("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .expect("OPENSHELL_E2E_GATEWAY_ARGS_FILE is set for a managed gateway");
        let raw = std::fs::read(&args_file).expect("read gateway args");
        let args: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect();
        args.iter()
            .position(|arg| arg == "--config")
            .and_then(|index| args.get(index + 1))
            .map(PathBuf::from)
            .expect("gateway args include --config")
    }

    /// Host that both the gateway process and the host-networked Docker
    /// supervisor use to reach this machine: the host of the driver's
    /// gateway endpoint.
    fn shared_host(config: &str) -> String {
        let driver = config
            .find("[openshell.drivers.docker]")
            .expect("gateway config has a Docker driver table");
        let endpoint = config[driver..]
            .lines()
            .find_map(|line| line.trim().strip_prefix("grpc_endpoint = "))
            .expect("Docker driver grpc_endpoint")
            .trim_matches('"');
        let authority = endpoint
            .split_once("://")
            .map_or(endpoint, |(_, rest)| rest);
        let host = authority
            .rsplit_once(':')
            .map_or(authority, |(host, _)| host);
        host.trim_start_matches('[')
            .trim_end_matches(']')
            .to_string()
    }

    async fn apply(guard_port: u16) -> Self {
        let config_path = Self::config_path();
        let original = std::fs::read(&config_path).expect("read gateway config");
        let config = String::from_utf8(original.clone()).expect("UTF-8 gateway config");
        let host = Self::shared_host(&config);
        let registration = format!(
            "\n[[openshell.supervisor.middleware]]\nname = \"{REGISTRATION}\"\ngrpc_endpoint = \"http://{host}:{guard_port}\"\nallow_insecure_transport = true\nmax_payload_bytes = 262144\ntimeout = \"2s\"\n"
        );
        std::fs::write(&config_path, format!("{config}{registration}"))
            .expect("write gateway config");
        let guard = Self {
            config_path,
            original,
        };
        restart_gateway().await;
        guard
    }

    async fn restore(self) {
        std::fs::write(&self.config_path, &self.original).expect("restore gateway config");
        restart_gateway().await;
        std::mem::forget(self);
    }
}

impl Drop for GatewayRegistration {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.config_path, &self.original);
        if let Ok(Some(gateway)) = ManagedGateway::from_env() {
            let _ = gateway.stop();
            let _ = gateway.start();
        }
    }
}

async fn restart_gateway() {
    let gateway = ManagedGateway::from_env()
        .expect("managed gateway metadata")
        .expect("managed gateway");
    gateway.stop().expect("stop gateway");
    gateway.start().expect("start gateway");
    wait_for_healthy(Duration::from_secs(120))
        .await
        .expect("gateway healthy with the legacy middleware registered");
}

/// `(request target, request body)` for every request the upstream served.
type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Minimal HTTP/1.1 upstream on the host. Every response closes its
/// connection. `POST /echo` returns the request body.
struct Upstream {
    port: u16,
    received: Received,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind upstream");
        let port = listener.local_addr().expect("upstream address").port();
        let received = Arc::new(Mutex::new(Vec::new()));
        let task_received = Arc::clone(&received);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let received = Arc::clone(&task_received);
                tokio::spawn(async move {
                    let _ = serve_one(stream, received).await;
                });
            }
        });
        Self {
            port,
            received,
            task,
        }
    }

    fn received(&self, path: &str) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|(target, _)| target == path)
            .map(|(_, body)| body.clone())
            .collect()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_one(mut stream: TcpStream, received: Received) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 4096];
    let (head_end, length) = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..read]);
        if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
            let length = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .map_or(0, |value| value.trim().parse::<usize>().unwrap_or(0));
            break (end + 4, length);
        }
    };
    while request.len() < head_end + length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    let request_line = String::from_utf8_lossy(&request[..head_end])
        .lines()
        .next()
        .unwrap_or_default()
        .to_string();
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let body = request[head_end..].to_vec();
    received
        .lock()
        .unwrap()
        .push((target.clone(), body.clone()));

    let (content_type, response_body) = match target.as_str() {
        "/echo" => ("application/octet-stream", body),
        "/sensitive" => ("text/plain", SENSITIVE_BODY.as_bytes().to_vec()),
        "/clean" => ("text/plain", CLEAN_BODY.as_bytes().to_vec()),
        "/binary" => ("application/octet-stream", BINARY_BODY.to_vec()),
        _ => ("text/plain", b"not found".to_vec()),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response_body).await?;
    stream.shutdown().await
}

/// Raw TCP echo server for the `tls: skip` endpoint.
struct EchoServer {
    port: u16,
    observed: Arc<Mutex<Vec<u8>>>,
    task: JoinHandle<()>,
}

impl EchoServer {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind echo server");
        let port = listener.local_addr().expect("echo address").port();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let task_observed = Arc::clone(&observed);
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let observed = Arc::clone(&task_observed);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    while let Ok(read) = stream.read(&mut buffer).await {
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
        Self {
            port,
            observed,
            task,
        }
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct PolicyCase<'a> {
    mode: &'a str,
    on_error: &'a str,
    /// Port of a `tls: skip` endpoint the attachment also selects.
    tls_skip_port: Option<u16>,
}

fn write_policy(upstream_port: u16, case: &PolicyCase<'_>) -> NamedTempFile {
    let replacement = if case.mode == "redact" {
        "      replacement: \"[FILTERED]\"\n"
    } else {
        ""
    };
    let tls_skip_endpoint = case.tls_skip_port.map_or_else(String::new, |port| {
        format!("      - host: {SANDBOX_HOST}\n        port: {port}\n        tls: skip\n{PRIVATE_ALLOWED_IPS}\n")
    });
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
  legacy-content-guard:
    name: Legacy content guard
    middleware: {REGISTRATION}
    order: 10
    config:
      mode: {mode}
      terms:
        - prototype-secret
        - internal-only
{replacement}    on_error: {on_error}
    endpoints:
      include: ["{SANDBOX_HOST}"]

network_policies:
  legacy_guard_upstream:
    name: legacy_guard_upstream
    endpoints:
      - host: {SANDBOX_HOST}
        port: {upstream_port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: POST
              path: /echo
          - allow:
              method: GET
              path: /sensitive
          - allow:
              method: GET
              path: /clean
          - allow:
              method: GET
              path: /binary
{PRIVATE_ALLOWED_IPS}
{tls_skip_endpoint}    binaries:
      - path: "/**"
"#,
        mode = case.mode,
        on_error = case.on_error,
    );
    let mut file = NamedTempFile::new().expect("create policy file");
    file.write_all(policy.as_bytes()).expect("write policy");
    file.flush().expect("flush policy");
    file
}

fn workload_script(upstream_port: u16, tls_skip_port: Option<u16>) -> String {
    format!(
        r#"
import http.client
import json
import socket

HOST = "{SANDBOX_HOST}"
PORT = {upstream_port}
TLS_SKIP_PORT = {tls_skip_port}

def call(method, path, body=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    headers = {{"Content-Type": "application/octet-stream"}} if body is not None else {{}}
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return {{"status": response.status, "body": data.decode("latin-1")}}

results = {{
    "echo_term": call("POST", "/echo", b'{{"note":"prototype-secret"}}'),
    "echo_binary": call("POST", "/echo", b"\xff\xfeprototype-secret"),
    "sensitive": call("GET", "/sensitive"),
    "clean": call("GET", "/clean"),
    "binary": call("GET", "/binary"),
}}
if TLS_SKIP_PORT:
    payload = bytes([0x00, 0xff, 0x13, 0x37]) + b"prototype-secret"
    with socket.create_connection((HOST, TLS_SKIP_PORT), timeout=30) as sock:
        sock.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            chunk = sock.recv(len(payload) - len(echoed))
            if not chunk:
                break
            echoed += chunk
    results["tls_skip"] = echoed.hex()
print(json.dumps(results, sort_keys=True))
"#,
        tls_skip_port = tls_skip_port.map_or_else(|| "None".to_string(), |port| port.to_string()),
    )
}

async fn run_workload(upstream: &Upstream, case: &PolicyCase<'_>) -> Value {
    let policy = write_policy(upstream.port, case);
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let script = workload_script(upstream.port, case.tls_skip_port);
    let mut sandbox =
        SandboxGuard::create(&["--policy", policy_path, "--", "python3", "-c", &script])
            .await
            .unwrap_or_else(|error| panic!("{} {} sandbox: {error}", case.mode, case.on_error));
    let result = sandbox
        .create_output
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line.trim()).ok())
        .next_back()
        .unwrap_or_else(|| panic!("missing workload result:\n{}", sandbox.create_output));
    sandbox.cleanup().await;
    result
}

fn assert_response(result: &Value, name: &str, status: u64, body: &str) {
    assert_eq!(result[name]["status"], status, "{name}: {result}");
    assert_eq!(result[name]["body"], body, "{name}: {result}");
}

fn assert_platform_error(result: &Value, name: &str, status: u64, error: &str) -> Value {
    assert_eq!(result[name]["status"], status, "{name}: {result}");
    let body: Value = serde_json::from_str(result[name]["body"].as_str().unwrap_or_default())
        .unwrap_or_else(|_| panic!("{name} returns a JSON error: {result}"));
    assert_eq!(body["error"], error, "{name}: {body}");
    body
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

fn should_run() -> Option<String> {
    let required = std::env::var(REQUIRE_ENV).as_deref() == Ok("1");
    let skip = |reason: &str| {
        assert!(!required, "{REQUIRE_ENV}=1 but {reason}");
        eprintln!("Skipping legacy middleware e2e: {reason}");
        None
    };
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("docker") {
        return skip("the e2e driver is not docker");
    }
    if std::env::var("OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER").as_deref() == Ok("1") {
        return skip("the external Docker driver does not read gateway config");
    }
    match ManagedGateway::from_env() {
        Ok(Some(_)) => {}
        Ok(None) => return skip("the gateway is not managed by this run"),
        Err(error) => panic!("load managed gateway metadata: {error}"),
    }
    match std::env::var(BIN_ENV) {
        Ok(binary) if !binary.is_empty() => Some(binary),
        _ => skip(&format!(
            "{BIN_ENV} is not set; run `mise run e2e:middleware-legacy`"
        )),
    }
}

#[tokio::test]
#[serial(supervisor_middleware_legacy)]
async fn v0_1_2_content_guard_runs_against_the_current_gateway_and_supervisor() {
    let Some(binary) = should_run() else {
        return;
    };
    let guard = LegacyContentGuard::start(&binary).await;
    let upstream = Upstream::start().await;
    let echo = EchoServer::start().await;
    let registration = GatewayRegistration::apply(guard.port).await;

    let redact = run_workload(
        &upstream,
        &PolicyCase {
            mode: "redact",
            on_error: "fail_closed",
            tls_skip_port: None,
        },
    )
    .await;
    assert_response(&redact, "echo_term", 200, r#"{"note":"[FILTERED]"}"#);
    assert_response(
        &redact,
        "sensitive",
        200,
        "contains [FILTERED] and [FILTERED]",
    );
    assert_response(&redact, "clean", 200, CLEAN_BODY);
    // The guard rejects bodies that are not UTF-8.
    assert_platform_error(&redact, "echo_binary", 403, "middleware_failed");
    assert_platform_error(&redact, "binary", 502, "response_delivery_failed");
    assert!(
        upstream
            .received("/echo")
            .contains(&br#"{"note":"[FILTERED]"}"#.to_vec()),
        "the upstream receives the redacted body"
    );

    let deny = run_workload(
        &upstream,
        &PolicyCase {
            mode: "deny",
            on_error: "fail_closed",
            tls_skip_port: None,
        },
    )
    .await;
    for name in ["echo_term", "sensitive"] {
        let body = assert_platform_error(&deny, name, 403, "middleware_denied");
        assert_eq!(body["reason_code"], "content_match", "{name}: {body}");
        assert!(!body.to_string().contains("prototype-secret"), "{body}");
    }
    assert_response(&deny, "clean", 200, CLEAN_BODY);

    let echo_requests_before = upstream.received("/echo").len();
    let fail_open = run_workload(
        &upstream,
        &PolicyCase {
            mode: "redact",
            on_error: "fail_open",
            tls_skip_port: Some(echo.port),
        },
    )
    .await;
    assert_response(&fail_open, "echo_term", 200, r#"{"note":"[FILTERED]"}"#);
    assert_response(&fail_open, "echo_binary", 200, &latin1(BINARY_BODY));
    assert_response(&fail_open, "binary", 200, &latin1(BINARY_BODY));
    assert_eq!(
        upstream.received("/echo")[echo_requests_before..],
        [br#"{"note":"[FILTERED]"}"#.to_vec(), BINARY_BODY.to_vec()],
        "fail_open forwards the body the guard rejected unchanged"
    );
    let raw: Vec<u8> = [0x00, 0xff, 0x13, 0x37]
        .into_iter()
        .chain(*b"prototype-secret")
        .collect();
    assert_eq!(
        fail_open["tls_skip"],
        hex::encode(&raw),
        "the tls: skip endpoint is relayed raw: {fail_open}"
    );
    assert_eq!(*echo.observed.lock().unwrap(), raw);

    registration.restore().await;
    drop(guard);
}
