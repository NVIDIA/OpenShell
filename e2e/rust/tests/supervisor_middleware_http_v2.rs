// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! HTTP middleware protocol 2 end to end.
//!
//! Runs the `supervisor-middleware-content-guard` example from this checkout
//! as an operator-registered middleware service for the current gateway and
//! Docker sandbox supervisor. `mise run e2e:middleware-http-v2` builds the
//! example and exports `OPENSHELL_E2E_CONTENT_GUARD_BIN`; without it the test
//! skips, unless `OPENSHELL_E2E_REQUIRE_MIDDLEWARE=1` makes the binary
//! mandatory.
//!
//! The test registers the service in the managed gateway config, restarts
//! the gateway (which describes it), and checks with sandboxes that:
//! - BUFFERED redacts and denies request and response bodies;
//! - STREAM carries a request body larger than any BUFFERED limit;
//! - STREAM delivers server-sent events one by one;
//! - a preflight rejection never contacts the upstream;
//! - a `tls: skip` tunnel is denied by default and allowed when the guard is
//!   configured to allow uninspectable traffic;
//! - a policy that mixes HTTP protocols on one destination is rejected at
//!   `policy set`.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_healthy};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use serial_test::serial;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;

const BIN_ENV: &str = "OPENSHELL_E2E_CONTENT_GUARD_BIN";
const REQUIRE_ENV: &str = "OPENSHELL_E2E_REQUIRE_MIDDLEWARE";
/// Operator registration name used by the policies.
const REGISTRATION: &str = "content-guard-example";
const SANDBOX_HOST: &str = "host.openshell.internal";
const SENSITIVE_BODY: &str = "contains prototype-secret and internal-only";
const CLEAN_BODY: &str = "ordinary public text";
const PRIVATE_ALLOWED_IPS: &str = r#"        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7""#;

/// The content guard, run as a host process.
struct ContentGuard {
    child: tokio::process::Child,
    port: u16,
}

impl ContentGuard {
    async fn start(binary: &str) -> Self {
        let port = find_free_port();
        let child = tokio::process::Command::new(binary)
            .arg("--bind")
            .arg(format!("0.0.0.0:{port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .unwrap_or_else(|error| panic!("start content guard '{binary}': {error}"));
        wait_for_port("127.0.0.1", port, Duration::from_secs(30))
            .await
            .expect("content guard listens");
        Self { child, port }
    }
}

impl Drop for ContentGuard {
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
        .expect("gateway healthy with the middleware registered");
}

/// `(request target, request body)` for every request the upstream served.
type Received = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// Minimal HTTP/1.1 upstream on the host. It accepts `Content-Length` and
/// chunked request bodies, and every response closes its connection.
///
/// - `POST /echo` returns the request body.
/// - `GET /sensitive` and `GET /clean` return fixed text.
/// - `GET /events` streams two server-sent events. It sends the second only
///   after `POST /ack`, or marks it `late` after a timeout, so a client that
///   acknowledges the first event proves it arrived on its own.
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
        let acknowledged = Arc::new(Notify::new());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let received = Arc::clone(&task_received);
                let acknowledged = Arc::clone(&acknowledged);
                tokio::spawn(async move {
                    let _ = serve_one(stream, received, acknowledged).await;
                });
            }
        });
        Self {
            port,
            received,
            task,
        }
    }

    fn targets(&self) -> Vec<String> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .map(|(target, _)| target.clone())
            .collect()
    }

    fn bodies(&self, target: &str) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .unwrap()
            .iter()
            .filter(|(received, _)| received == target)
            .map(|(_, body)| body.clone())
            .collect()
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(
    stream: &mut BufReader<TcpStream>,
) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await? == 0 {
        return Ok(None);
    }
    let target = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let mut length = 0;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        stream.read_line(&mut line).await?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(value) = lower.strip_prefix("content-length:") {
            length = value.trim().parse().unwrap_or(0);
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
    }
    let mut body = Vec::new();
    if chunked {
        loop {
            let mut size = String::new();
            stream.read_line(&mut size).await?;
            let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
                .unwrap_or(0);
            if size == 0 {
                // Trailer section.
                loop {
                    let mut line = String::new();
                    stream.read_line(&mut line).await?;
                    if line.trim_end().is_empty() {
                        break;
                    }
                }
                break;
            }
            let mut chunk = vec![0; size + 2];
            stream.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk[..size]);
        }
    } else {
        body.resize(length, 0);
        stream.read_exact(&mut body).await?;
    }
    Ok(Some((target, body)))
}

async fn serve_one(
    stream: TcpStream,
    received: Received,
    acknowledged: Arc<Notify>,
) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    let Some((target, body)) = read_request(&mut stream).await? else {
        return Ok(());
    };
    received
        .lock()
        .unwrap()
        .push((target.clone(), body.clone()));
    let mut stream = stream.into_inner();
    if target == "/events" {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n")
            .await?;
        write_chunk(&mut stream, b"data: one prototype-secret\n\n").await?;
        let second =
            match tokio::time::timeout(Duration::from_secs(20), acknowledged.notified()).await {
                Ok(()) => &b"data: two\n\n"[..],
                Err(_) => b"data: late\n\n",
            };
        write_chunk(&mut stream, second).await?;
        stream.write_all(b"0\r\n\r\n").await?;
        return stream.shutdown().await;
    }
    if target == "/ack" {
        acknowledged.notify_one();
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            .await?;
        return stream.shutdown().await;
    }
    let (content_type, response_body) = match target.as_str() {
        "/echo" => ("application/octet-stream", body),
        "/sensitive" => ("text/plain", SENSITIVE_BODY.as_bytes().to_vec()),
        _ => ("text/plain", CLEAN_BODY.as_bytes().to_vec()),
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&response_body).await?;
    stream.shutdown().await
}

async fn write_chunk(stream: &mut TcpStream, data: &[u8]) -> std::io::Result<()> {
    stream
        .write_all(format!("{:X}\r\n", data.len()).as_bytes())
        .await?;
    stream.write_all(data).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
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
    body_mode: &'a str,
    uninspectable: &'a str,
    /// Port of a `tls: skip` endpoint the attachment also selects.
    tls_skip_port: Option<u16>,
    /// Also attach `openshell/regex` (HTTP protocol 1) to the same host.
    mixed: bool,
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
    let regex = if case.mixed {
        r#"  regex-redactor:
    middleware: openshell/regex
    order: 20
    config:
      mode: redact
    endpoints:
      include: ["*.openshell.internal"]
"#
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
  content-guard:
    name: Content guard
    middleware: {REGISTRATION}
    order: 10
    config:
      mode: {mode}
      body_mode: {body_mode}
      uninspectable: {uninspectable}
      terms:
        - prototype-secret
        - internal-only
{replacement}    on_error: fail_closed
    endpoints:
      include: ["{SANDBOX_HOST}"]
{regex}
network_policies:
  guard_upstream:
    name: guard_upstream
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
              method: POST
              path: /ack
          - allow:
              method: GET
              path: /sensitive
          - allow:
              method: GET
              path: /clean
          - allow:
              method: GET
              path: /events
{PRIVATE_ALLOWED_IPS}
{tls_skip_endpoint}    binaries:
      - path: "/**"
"#,
        mode = case.mode,
        body_mode = case.body_mode,
        uninspectable = case.uninspectable,
    );
    let mut file = NamedTempFile::new().expect("create policy file");
    file.write_all(policy.as_bytes()).expect("write policy");
    file.flush().expect("flush policy");
    file
}

/// Upload size larger than any BUFFERED limit (256 KiB), so only STREAM can
/// carry it.
const LARGE_UPLOAD_LINES: usize = 600;

fn workload_script(upstream_port: u16, case: &PolicyCase<'_>) -> String {
    format!(
        r#"
import http.client
import json
import socket

HOST = "{SANDBOX_HOST}"
PORT = {upstream_port}
TLS_SKIP_PORT = {tls_skip_port}
STREAM = {stream}

def call(method, path, body=None):
    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    headers = {{"Content-Type": "application/octet-stream"}} if body is not None else {{}}
    conn.request(method, path, body=body, headers=headers)
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return {{"status": response.status, "body": data.decode("latin-1")}}

results = {{
    "echo_term": call("POST", "/echo", b'{{"note":"prototype-secret"}}'),
    "sensitive": call("GET", "/sensitive"),
    "clean": call("GET", "/clean"),
    "target_term": call("GET", "/clean?q=prototype-secret"),
}}

if STREAM:
    upload = (b"x" * 1000 + b" prototype-secret\n") * {LARGE_UPLOAD_LINES}
    echoed = call("POST", "/echo", upload)
    expected = upload.replace(b"prototype-secret", b"[FILTERED]")
    results["large_upload"] = {{
        "status": echoed["status"],
        "sent_bytes": len(upload),
        "redacted": echoed["body"].encode("latin-1") == expected,
    }}

    conn = http.client.HTTPConnection(HOST, PORT, timeout=60)
    conn.request("GET", "/events")
    response = conn.getresponse()
    first = b""
    while not first.endswith(b"\n\n"):
        line = response.readline()
        if not line:
            break
        first += line
    acknowledged = call("POST", "/ack")
    rest = response.read()
    conn.close()
    results["events"] = {{
        "status": response.status,
        "first": first.decode("utf-8"),
        "ack": acknowledged["status"],
        "rest": rest.decode("utf-8"),
    }}

if TLS_SKIP_PORT:
    payload = bytes([0x00, 0xff, 0x13, 0x37]) + b"prototype-secret"
    try:
        with socket.create_connection((HOST, TLS_SKIP_PORT), timeout=30) as sock:
            sock.sendall(payload)
            echoed = b""
            while len(echoed) < len(payload):
                chunk = sock.recv(len(payload) - len(echoed))
                if not chunk:
                    break
                echoed += chunk
        results["tls_skip"] = echoed.hex()
    except OSError as error:
        results["tls_skip"] = "error: " + type(error).__name__
print(json.dumps(results, sort_keys=True))
"#,
        tls_skip_port = case
            .tls_skip_port
            .map_or_else(|| "None".to_string(), |port| port.to_string()),
        stream = if case.body_mode == "stream" {
            "True"
        } else {
            "False"
        },
    )
}

async fn run_workload(upstream: &Upstream, case: &PolicyCase<'_>) -> Value {
    let policy = write_policy(upstream.port, case);
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let script = workload_script(upstream.port, case);
    let mut sandbox =
        SandboxGuard::create(&["--policy", policy_path, "--", "python3", "-c", &script])
            .await
            .unwrap_or_else(|error| panic!("{} {} sandbox: {error}", case.mode, case.body_mode));
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

fn tls_skip_payload() -> Vec<u8> {
    [0x00, 0xff, 0x13, 0x37]
        .into_iter()
        .chain(*b"prototype-secret")
        .collect()
}

fn should_run() -> Option<String> {
    let required = std::env::var(REQUIRE_ENV).as_deref() == Ok("1");
    let skip = |reason: &str| {
        assert!(!required, "{REQUIRE_ENV}=1 but {reason}");
        eprintln!("Skipping HTTP protocol 2 middleware e2e: {reason}");
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
            "{BIN_ENV} is not set; run `mise run e2e:middleware-http-v2`"
        )),
    }
}

#[tokio::test]
#[serial(supervisor_middleware)]
async fn http_protocol_2_content_guard_runs_against_the_gateway_and_supervisor() {
    let Some(binary) = should_run() else {
        return;
    };
    let guard = ContentGuard::start(&binary).await;
    let upstream = Upstream::start().await;
    let echo = EchoServer::start().await;
    let registration = GatewayRegistration::apply(guard.port).await;

    // BUFFERED redaction in both directions, a preflight rejection, and a
    // `tls: skip` tunnel denied by default.
    let redact = run_workload(
        &upstream,
        &PolicyCase {
            mode: "redact",
            body_mode: "buffered",
            uninspectable: "deny",
            tls_skip_port: Some(echo.port),
            mixed: false,
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
    assert!(
        upstream
            .bodies("/echo")
            .contains(&br#"{"note":"[FILTERED]"}"#.to_vec()),
        "the upstream receives the redacted body"
    );
    let rejected = assert_platform_error(&redact, "target_term", 403, "middleware_denied");
    assert_eq!(rejected["reason_code"], "content_match", "{rejected}");
    assert!(
        upstream
            .targets()
            .iter()
            .all(|target| !target.contains("prototype-secret")),
        "a preflight rejection never contacts the upstream"
    );
    assert_ne!(
        redact["tls_skip"],
        hex::encode(tls_skip_payload()),
        "the guard denies uninspectable traffic by default: {redact}"
    );
    assert!(echo.observed.lock().unwrap().is_empty());

    // BUFFERED denial in both directions.
    let echo_bodies_before = upstream.bodies("/echo").len();
    let deny = run_workload(
        &upstream,
        &PolicyCase {
            mode: "deny",
            body_mode: "buffered",
            uninspectable: "deny",
            tls_skip_port: None,
            mixed: false,
        },
    )
    .await;
    for name in ["echo_term", "sensitive"] {
        let body = assert_platform_error(&deny, name, 403, "middleware_denied");
        assert_eq!(body["reason_code"], "content_match", "{name}: {body}");
        assert!(!body.to_string().contains("prototype-secret"), "{body}");
    }
    assert_response(&deny, "clean", 200, CLEAN_BODY);
    assert_eq!(
        upstream.bodies("/echo").len(),
        echo_bodies_before,
        "a denied request body never reaches the upstream"
    );

    // STREAM: a large upload, server-sent events one by one, and an allowed
    // `tls: skip` tunnel.
    let stream = run_workload(
        &upstream,
        &PolicyCase {
            mode: "redact",
            body_mode: "stream",
            uninspectable: "allow",
            tls_skip_port: Some(echo.port),
            mixed: false,
        },
    )
    .await;
    assert_response(&stream, "echo_term", 200, r#"{"note":"[FILTERED]"}"#);
    assert_eq!(stream["large_upload"]["status"], 200, "{stream}");
    assert_eq!(stream["large_upload"]["redacted"], true, "{stream}");
    let large = upstream
        .bodies("/echo")
        .into_iter()
        .max_by_key(Vec::len)
        .expect("the upstream received the large upload");
    assert!(
        large.len() > 256 * 1024,
        "the large upload exceeds every BUFFERED limit"
    );
    assert!(!String::from_utf8_lossy(&large).contains("prototype-secret"));
    assert_eq!(stream["events"]["status"], 200, "{stream}");
    assert_eq!(
        stream["events"]["first"], "data: one [FILTERED]\n\n",
        "{stream}"
    );
    assert_eq!(stream["events"]["ack"], 204, "{stream}");
    assert_eq!(
        stream["events"]["rest"], "data: two\n\n",
        "the first event reached the sandbox before the second was sent: {stream}"
    );
    assert_eq!(
        stream["tls_skip"],
        hex::encode(tls_skip_payload()),
        "the guard allows uninspectable traffic when configured to: {stream}"
    );

    // A policy that runs both HTTP protocols for one destination is rejected.
    let base = write_policy(
        upstream.port,
        &PolicyCase {
            mode: "redact",
            body_mode: "buffered",
            uninspectable: "deny",
            tls_skip_port: None,
            mixed: false,
        },
    );
    let mixed = write_policy(
        upstream.port,
        &PolicyCase {
            mode: "redact",
            body_mode: "buffered",
            uninspectable: "deny",
            tls_skip_port: None,
            mixed: true,
        },
    );
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &[
            "--policy",
            base.path().to_str().expect("UTF-8 policy path"),
            "--no-tty",
        ],
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create sandbox with the content guard");
    let (output, exit_code) = run_cli(&[
        "policy",
        "set",
        &sandbox.name,
        "--policy",
        mixed.path().to_str().expect("UTF-8 policy path"),
    ])
    .await;
    assert_ne!(
        exit_code, 0,
        "a mixed-protocol policy is rejected:\n{output}"
    );
    // The CLI wraps long errors across lines.
    let message = output
        .replace('│', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        message.contains("separate their endpoint selectors"),
        "the rejection says how to fix the policy:\n{output}"
    );
    sandbox.cleanup().await;

    registration.restore().await;
    drop(guard);
}
