// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Provider changes acknowledged through a real sandbox HTTPS request path.
//!
//! Attach, update, and detach wait for confirmation of their exact saved changes.
//! Clients launched after attach and update keep their own static references.
//! The first request from the updated launch uses the acknowledged credential;
//! detach revokes both retained references and removes them from future launches.
//! Only the synthetic backends and privileged provider CLI receive keys;
//! workload files, responses, and diagnostics contain status information only.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_network_name};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Instant, sleep, timeout};

const TOKEN_ENV: &str = "PROVIDER_READINESS_E2E_TOKEN";
const BACKEND_PORT: u16 = 8443;
const OTHER_BACKEND_PORT: u16 = 8444;
const READY: &str = "provider-readiness-client-ready";
const CONTROL: &str = "/sandbox/provider-readiness-probe";
const RESULT: &str = "/sandbox/provider-readiness-result";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(300);
const READINESS_TIMEOUT_SECONDS: &str = "90";
const READINESS_COMMAND_TIMEOUT: Duration = Duration::from_secs(105);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(120);

// Keys arrive on a private stdin pipe after process creation. Neither the
// command line nor any file contains them, and HTTP/server errors are silent.
const BACKEND: &str = r"
import http.server, json, ssl, sys, threading

config = json.loads(sys.stdin.readline())
keys = config.pop('keys')
lock = threading.Lock()
state = {'phase': 0, 'total': 0, 'accepted': [0, 0], 'rejected': 0}

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        pass

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        with lock:
            phase = state['phase']
            valid = self.headers.get('Authorization') == 'Bearer ' + keys[phase]
            state['total'] += 1
            if valid:
                state['accepted'][phase] += 1
            else:
                state['rejected'] += 1
        body = json.dumps({'authorized': valid, 'phase': phase}).encode()
        self.send_response(200 if valid else 401)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(config['certificate'], config['private_key'])
servers = []
for port in config['ports']:
    server = Server(('0.0.0.0', port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    servers.append(server)
print(json.dumps({'ready': True}), flush=True)

for line in sys.stdin:
    request = json.loads(line)
    with lock:
        if request['command'] == 'rotate':
            state['phase'] = 1
        print(json.dumps(state), flush=True)
for server in servers:
    server.shutdown()
    server.server_close()
";

// This source is safe to place in the workload image: it contains environment
// key names and endpoint coordinates, but never a key value or issued handle.
const CLIENT: &str = r"
import json, os, pathlib, re, ssl, sys, time, urllib.error, urllib.request

config = json.loads(sys.argv[1])
key = 'PROVIDER_READINESS_E2E_TOKEN'
token = os.environ.get(key, '')
if not re.fullmatch(r'openshell:resolve:env:v[1-9][0-9]*_' + key, token):
    print('client did not receive a revision-scoped reference', flush=True)
    sys.exit(64)
client = sys.argv[2]
if client not in ('a', 'b'):
    sys.exit(64)
pid = os.getpid()
control = pathlib.Path('/sandbox/provider-readiness-probe-' + client)
result = pathlib.Path('/sandbox/provider-readiness-result-' + client)

def probe(phase):
    host, port, path = config['host'], config['port'], '/v1/chat/completions'
    target = phase[:-8] if phase.endswith('_control') else phase
    if target == 'wrong_host':
        host = config['other_host']
    elif target == 'wrong_port':
        port = config['other_port']
    elif target == 'wrong_path':
        path = '/outside'
    url = 'https://%s:%s%s' % (host, port, path)
    response = {'phase': phase, 'pid': pid, 'same_reference': os.environ.get(key) == token,
                'ok': False, 'status': 0, 'backend_phase': -1}
    try:
        context = ssl.create_default_context()
        if phase == 'untrusted_ca':
            # An empty trust store proves this client does verify TLS.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        headers = {'Content-Type': 'application/json'}
        if not phase.endswith('_control'):
            headers['Authorization'] = 'Bearer ' + token
        request = urllib.request.Request(url, data=b'{}', headers=headers)
        try:
            reply = urllib.request.urlopen(request, context=context, timeout=5)
        except urllib.error.HTTPError as error:
            # The backend's safe 401 body proves the negative endpoint is
            # reachable before a credential-bearing request is denied.
            reply = error
        with reply:
            body = json.loads(reply.read(1024))
            response['ok'] = body.get('authorized') is True
            response['status'] = reply.status
            response['backend_phase'] = body.get('phase', -1)
    except Exception as error:
        # HTTP/TLS exceptions can embed headers; expose only fixed type names.
        response['error_kind'] = type(error).__name__
        response['reason_kind'] = type(getattr(error, 'reason', None)).__name__
    return response

print('provider-readiness-client-ready', flush=True)
deadline = time.monotonic() + 600
while time.monotonic() < deadline:
    if control.exists():
        phase = control.read_text().strip()
        control.unlink()
        temporary = result.with_suffix('.tmp')
        temporary.write_text(json.dumps(probe(phase)))
        temporary.replace(result)
    time.sleep(0.05)
";

struct FixtureImage {
    engine: ContainerEngine,
    tag: String,
}

impl FixtureImage {
    fn new() -> Result<Self, String> {
        Ok(Self {
            engine: ContainerEngine::from_env()?,
            tag: format!(
                "localhost/openshell-e2e-readiness-{}-{:016x}:latest",
                std::process::id(),
                rand::random::<u64>(),
            ),
        })
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    async fn build(&self, dockerfile: &Path, context: &Path, label: &str) -> Result<(), String> {
        let mut command = Command::from(self.engine.command());
        command
            .args(["build", "--file"])
            .arg(dockerfile)
            .args(["--tag", &self.tag])
            .arg(context);
        checked_command_with_timeout(&mut command, label, IMAGE_BUILD_TIMEOUT)
            .await
            .map(|_| ())
    }

    async fn remove(&self) -> Result<(), String> {
        let mut command = Command::from(self.engine.command());
        command.args(["image", "rm", "--force", &self.tag]);
        // Teardown is explicit and bounded. This type has no Drop subprocess
        // that could block the test runtime after the removal deadline expires.
        checked_command(&mut command, "remove fixture image")
            .await
            .map(|_| ())
    }
}

// This fixture owns the only test in its binary. The wrapper's gateway is
// private to this run, so replacing its supervisor image cannot affect another
// test while the public fixture CA is installed in the supervisor trust store.
struct GatewayTrustConfig {
    path: PathBuf,
    original: String,
    image_range: std::ops::Range<usize>,
    supervisor_image: String,
    health_port: u16,
    restore_required: bool,
}

impl GatewayTrustConfig {
    fn load() -> Result<Self, String> {
        if std::env::var_os("OPENSHELL_GATEWAY_ENDPOINT").is_some()
            || std::env::var_os("OPENSHELL_E2E_GATEWAY_BIN").is_none()
            || std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("docker")
            || std::env::var("OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER")
                .is_ok_and(|value| value != "0")
        {
            return Err("provider readiness fixture requires a wrapper-owned gateway with the bundled Docker driver".to_string());
        }
        let args_file = std::env::var_os("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .ok_or("managed gateway argument metadata is missing")?;
        let raw =
            std::fs::read(args_file).map_err(|_| "could not read managed gateway arguments")?;
        let args = raw
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(std::str::from_utf8)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "managed gateway arguments were not UTF-8")?;
        let argument = |name| {
            let mut values = args.windows(2).filter(|pair| pair[0] == name);
            let value = values.next().ok_or("managed gateway argument is missing")?[1];
            if values.next().is_some() {
                return Err("managed gateway argument is duplicated");
            }
            Ok(value)
        };
        let path = PathBuf::from(argument("--config")?);
        let health_port = argument("--health-port")?
            .parse::<u16>()
            .map_err(|_| "managed gateway health port is invalid")?;
        let original = std::fs::read_to_string(&path)
            .map_err(|_| "could not read managed gateway configuration")?;
        let (image_range, supervisor_image) = docker_supervisor_image(&original)?;
        Ok(Self {
            path,
            original,
            image_range,
            supervisor_image,
            health_port,
            restore_required: false,
        })
    }

    async fn apply(&mut self, image: &str) -> Result<(), String> {
        let mut updated = self.original.clone();
        updated.replace_range(self.image_range.clone(), image);
        // Set the guard before the write: a failed write or restart must still
        // flow through explicit restoration of the exact original bytes.
        self.restore_required = true;
        std::fs::write(&self.path, updated)
            .map_err(|_| "could not install fixture supervisor configuration")?;
        restart_fixture_gateway(self.health_port).await
    }

    async fn restore(&mut self) -> Result<(), String> {
        if !self.restore_required {
            return Ok(());
        }
        std::fs::write(&self.path, &self.original)
            .map_err(|_| "could not restore original gateway configuration")?;
        restart_fixture_gateway(self.health_port)
            .await
            .map_err(|_| "original gateway configuration was restored but restart failed")?;
        self.restore_required = false;
        Ok(())
    }
}

impl Drop for GatewayTrustConfig {
    fn drop(&mut self) {
        if self.restore_required {
            // Cancellation/panic fallback restores disk state only. Normal
            // Result paths explicitly restart and verify health; Drop never
            // launches a subprocess or hides a failed restart as success.
            let _ = std::fs::write(&self.path, &self.original);
        }
    }
}

fn docker_supervisor_image(config: &str) -> Result<(std::ops::Range<usize>, String), String> {
    let mut in_docker = false;
    let mut offset = 0;
    let mut found = None;
    for line in config.split_inclusive('\n') {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_docker = trimmed == "[openshell.drivers.docker]";
        } else if in_docker && let Some((key, value)) = trimmed.split_once('=') {
            if key.trim() == "socket_path" {
                return Err(
                    "fixture cannot replace an external Docker driver configuration".to_string(),
                );
            }
            if key.trim() == "supervisor_image" {
                // Accept only the wrapper's single-line quoted OCI reference.
                // Reject escapes/comments instead of treating general TOML as
                // text and accidentally changing a different configuration key.
                let image = value
                    .trim()
                    .strip_prefix('"')
                    .and_then(|value| value.strip_suffix('"'))
                    .filter(|image| {
                        !image.is_empty()
                            && image.bytes().all(|byte| {
                                byte.is_ascii_alphanumeric() || b"/:@._-".contains(&byte)
                            })
                    })
                    .ok_or("managed supervisor image is not a simple quoted OCI reference")?;
                let start = offset
                    + line
                        .find('"')
                        .ok_or("managed supervisor image is not quoted")?
                    + 1;
                if found
                    .replace((start..start + image.len(), image.to_string()))
                    .is_some()
                {
                    return Err("managed Docker supervisor image is duplicated".to_string());
                }
            }
        }
        offset += line.len();
    }
    found.ok_or_else(|| "managed Docker supervisor image is missing".to_string())
}

async fn restart_fixture_gateway(health_port: u16) -> Result<(), String> {
    let gateway = ManagedGateway::from_env()
        .map_err(|_| "could not load managed gateway restart metadata")?
        .ok_or("managed gateway restart metadata disappeared")?;
    // ManagedGateway bounds graceful shutdown before force-kill. Keep it local:
    // its Drop can start a stopped gateway, but never owns configuration restore.
    gateway
        .stop()
        .map_err(|_| "could not stop fixture gateway")?;
    gateway
        .start()
        .map_err(|_| "could not restart fixture gateway")?;
    let url = format!("http://127.0.0.1:{health_port}/healthz");
    let deadline = Instant::now() + GATEWAY_READY_TIMEOUT;
    loop {
        if checked_command(
            Command::new("curl").args(["--silent", "--fail", "--max-time", "2", &url]),
            "check fixture gateway health",
        )
        .await
        .is_ok()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("fixture gateway did not become healthy".to_string());
        }
        sleep(Duration::from_millis(250)).await;
    }
}

struct Backend {
    engine: ContainerEngine,
    name: String,
    network: String,
    namespace: String,
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<Lines<BufReader<ChildStdout>>>,
    launch_attempted: bool,
}

struct PersistentClient {
    child: Child,
    // Keep the stream open after reading the marker so the CLI can continue
    // relaying the same remote process until explicit sandbox teardown.
    _output: Lines<BufReader<ChildStdout>>,
}

impl PersistentClient {
    async fn start(
        sandbox: &SandboxGuard,
        python: &str,
        config: &str,
        client: &str,
    ) -> Result<Self, String> {
        let mut command = sandbox_command(
            sandbox,
            &[
                python,
                "-u",
                "/opt/provider-readiness-client.py",
                config,
                client,
            ],
        );
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "persistent workload exec could not start")?;
        let output = child
            .stdout
            .take()
            .ok_or("workload stdout was unavailable")?;
        let mut output = BufReader::new(output).lines();
        timeout(COMMAND_TIMEOUT, async {
            while let Some(line) = output
                .next_line()
                .await
                .map_err(|_| "workload marker could not be read")?
            {
                if line.trim() == READY {
                    return Ok(());
                }
                // A CLI or workload error can contain environment material.
                // Ignore every unrecognized line without including it in errors.
            }
            Err("persistent workload closed before its ready marker")
        })
        .await
        .map_err(|_| "persistent workload ready marker timed out")??;
        Ok(Self {
            child,
            _output: output,
        })
    }

    async fn stop(&mut self) -> Result<(), String> {
        // Sandbox deletion ends the remote workload; reap the retained relay
        // even if the remote deletion or normal stream shutdown fails.
        timeout(COMMAND_TIMEOUT, self.child.kill())
            .await
            .map_err(|_| "persistent client cleanup timed out")?
            .map_err(|_| "persistent client cleanup failed".to_string())
    }
}

impl Backend {
    fn new(name: String) -> Result<Self, String> {
        Ok(Self {
            engine: ContainerEngine::from_env()?,
            name,
            network: e2e_network_name().ok_or("fixture requires the managed Docker network")?,
            namespace: std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
                .map_err(|_| "fixture requires the managed Docker namespace")?,
            child: None,
            input: None,
            output: None,
            launch_attempted: false,
        })
    }

    async fn spawn(&mut self, base: &str, tls_directory: &Path) -> Result<String, String> {
        let tls_directory = tls_directory
            .to_str()
            .filter(|path| !path.contains([',', '\n', '\r']))
            .ok_or("fixture TLS mount path is invalid")?;
        let mount = format!("type=bind,src={tls_directory},dst=/fixture-tls,readonly");
        let namespace_label = format!("openshell.ai/sandbox-namespace={}", self.namespace);
        let mut command = Command::from(self.engine.command());
        command
            .args([
                "run",
                "--rm",
                "--interactive",
                "--pull=never",
                "--name",
                &self.name,
                "--network",
                &self.network,
                "--label",
                "openshell.ai/managed-by=openshell",
                "--label",
                &namespace_label,
                "--label",
                "openshell.ai/isolation-role=fixture",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--mount",
                &mount,
                "--entrypoint",
                "/usr/bin/python3",
                base,
                "-u",
                "-c",
                BACKEND,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        // Record the unique container name before creation. Every Result exit
        // removes it, including a failed readiness exchange after Docker starts.
        // Wrapper-scoped labels also let wrapper teardown reap an interrupted run.
        self.launch_attempted = true;
        let child = command
            .spawn()
            .map_err(|_| "could not start synthetic HTTPS backend".to_string())?;
        self.child = Some(child);
        let child = self.child.as_mut().ok_or("backend child was absent")?;
        self.input = Some(
            child
                .stdin
                .take()
                .ok_or("backend stdin was not available")?,
        );
        let output = child
            .stdout
            .take()
            .ok_or("backend stdout was not available")?;
        self.output = Some(BufReader::new(output).lines());
        // Python waits for its private stdin configuration before reading TLS
        // files. Discover the actual address first so its certificate can name
        // that exact endpoint without DNS or an unverified TLS connection.
        self.address().await
    }

    async fn address(&mut self) -> Result<String, String> {
        let deadline = Instant::now() + COMMAND_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("backend bridge address did not become available".to_string());
            }
            let mut inspect = Command::from(self.engine.command());
            inspect.args([
                "inspect",
                "--format",
                "{{json .NetworkSettings.Networks}}",
                &self.name,
            ]);
            if let Ok(output) = checked_command_with_timeout(
                &mut inspect,
                "inspect backend bridge address",
                remaining.min(Duration::from_secs(2)),
            )
            .await
            {
                let networks: Value = serde_json::from_str(&output)
                    .map_err(|_| "backend network metadata was invalid")?;
                if let Some(address) = networks[&self.network]["IPAddress"]
                    .as_str()
                    .filter(|address| !address.is_empty())
                {
                    let address = address
                        .parse::<Ipv4Addr>()
                        .map_err(|_| "backend network address was not IPv4")?;
                    if !address.is_private() {
                        return Err("fixture backend requires a private bridge address".to_string());
                    }
                    return Ok(address.to_string());
                }
            }
            if self
                .child
                .as_mut()
                .ok_or("backend child was absent")?
                .try_wait()
                .map_err(|_| "could not inspect backend client status")?
                .is_some()
            {
                return Err("backend exited before its bridge address was available".to_string());
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn initialize(&mut self, config: &Value) -> Result<(), String> {
        if self.exchange(config).await?["ready"] != true {
            return Err("synthetic HTTPS backend did not become ready".to_string());
        }
        Ok(())
    }

    async fn exchange(&mut self, request: &Value) -> Result<Value, String> {
        let mut bytes =
            serde_json::to_vec(request).map_err(|_| "backend request encoding failed")?;
        bytes.push(b'\n');
        let input = self.input.as_mut().ok_or("backend stdin was absent")?;
        let output = self.output.as_mut().ok_or("backend stdout was absent")?;
        timeout(COMMAND_TIMEOUT, async {
            input
                .write_all(&bytes)
                .await
                .map_err(|_| "backend control write failed")?;
            let line = output
                .next_line()
                .await
                .map_err(|_| "backend control read failed")?
                .ok_or("backend closed its control stream")?;
            serde_json::from_str(&line).map_err(|_| "backend status was not valid JSON")
        })
        .await
        .map_err(|_| "backend control operation timed out".to_string())?
        .map_err(str::to_string)
    }

    async fn stop(&mut self) -> Result<(), String> {
        // Closing stdin lets Python shut down normally. Removing the named
        // container also covers a stalled startup or disconnected Docker client;
        // killing the attached client alone cannot prove the container stopped.
        drop(self.input.take());
        let mut reap_result = Ok(());
        if let Some(child) = self.child.as_mut() {
            reap_result = timeout(COMMAND_TIMEOUT, child.kill())
                .await
                .map_err(|_| "backend client teardown timed out".to_string())
                .and_then(|result| {
                    result.map_err(|_| "backend client teardown failed".to_string())
                });
        }
        if !self.launch_attempted {
            return reap_result;
        }
        remove_fixture_container(&self.engine, &self.name).await?;
        reap_result
    }
}

/// Counters deliberately contain no authorization headers or secret values.
#[derive(Deserialize, Serialize)]
struct BackendCounts {
    phase: u8,
    total: u64,
    accepted: [u64; 2],
    rejected: u64,
}

// A second endpoint supplies a reachable wrong-host control. Each container
// retains its own counters; their sum proves denied traffic reaches neither.
struct BackendPair {
    backends: [Backend; 2],
}

impl BackendPair {
    fn new(name: &str) -> Result<Self, String> {
        Ok(Self {
            backends: [
                Backend::new(format!("{name}-backend"))?,
                Backend::new(format!("{name}-other-backend"))?,
            ],
        })
    }

    async fn spawn(&mut self, base: &str, tls_directory: &Path) -> Result<[String; 2], String> {
        let host = self.backends[0].spawn(base, tls_directory).await?;
        let other_host = self.backends[1].spawn(base, tls_directory).await?;
        if host == other_host {
            return Err("wrong-host control requires a distinct backend address".to_string());
        }
        Ok([host, other_host])
    }

    async fn initialize(&mut self, config: &Value) -> Result<(), String> {
        for backend in &mut self.backends {
            backend.initialize(config).await?;
        }
        Ok(())
    }

    async fn rotate(&mut self) -> Result<(), String> {
        for backend in &mut self.backends {
            if backend.exchange(&json!({"command": "rotate"})).await?["phase"] != 1 {
                return Err("backend did not switch to the replacement key".to_string());
            }
        }
        Ok(())
    }

    async fn counts(&mut self) -> Result<Value, String> {
        let mut combined: Option<BackendCounts> = None;
        for backend in &mut self.backends {
            let response = backend.exchange(&json!({"command": "snapshot"})).await?;
            let counters: BackendCounts =
                serde_json::from_value(response).map_err(|_| "backend counters were invalid")?;
            if let Some(total) = combined.as_mut() {
                if total.phase != counters.phase {
                    return Err("fixture backends disagree on the active key".to_string());
                }
                let add = |left: u64, right: u64| {
                    left.checked_add(right).ok_or("backend counters overflowed")
                };
                total.total = add(total.total, counters.total)?;
                total.rejected = add(total.rejected, counters.rejected)?;
                for (left, right) in total.accepted.iter_mut().zip(counters.accepted) {
                    *left = add(*left, right)?;
                }
            } else {
                combined = Some(counters);
            }
        }
        serde_json::to_value(combined.ok_or("backend counters were absent")?)
            .map_err(|_| "backend counters could not be encoded".to_string())
    }

    async fn stop(&mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        for backend in &mut self.backends {
            if let Err(error) = backend.stop().await {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

async fn checked_command(command: &mut Command, label: &str) -> Result<String, String> {
    checked_command_with_timeout(command, label, COMMAND_TIMEOUT).await
}

async fn checked_command_with_timeout(
    command: &mut Command,
    label: &str,
    max_wait: Duration,
) -> Result<String, String> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let output = timeout(max_wait, command.output())
        .await
        .map_err(|_| format!("{label} timed out"))?
        .map_err(|_| format!("{label} could not start"))?;
    if !output.status.success() {
        // CLI arguments, captured output, and subprocess errors can contain
        // credential material. Error messages expose only the safe operation.
        return Err(format!("{label} failed; subprocess output withheld"));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{label} returned invalid UTF-8"))
}

async fn cli(label: &str, args: &[&str], credential: Option<&str>) -> Result<String, String> {
    let mut command = openshell_cmd();
    command.args(args);
    if let Some(credential) = credential {
        command.env(TOKEN_ENV, credential);
    }
    checked_command(&mut command, label).await
}

fn sandbox_command(sandbox: &SandboxGuard, argv: &[&str]) -> Command {
    let mut command = openshell_cmd();
    command
        .args(["sandbox", "exec", "--name", &sandbox.name, "--no-tty", "--"])
        .args(argv);
    command
}

async fn generate_certificates(
    directory: &Path,
    host: &str,
    other_host: &str,
) -> Result<(PathBuf, PathBuf), String> {
    let ca_key = directory.join("ca.key.fixture");
    let ca = directory.join("ca.crt");
    let key = directory.join("backend.key.fixture");
    let csr = directory.join("backend.csr");
    let certificate = directory.join("backend.crt");
    let extensions = directory.join("backend.ext");
    std::fs::write(
        &extensions,
        format!(
            "basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:{host},IP:{other_host}\nextendedKeyUsage=serverAuth\n"
        ),
    )
    .map_err(|_| "could not write public TLS certificate extensions")?;
    checked_command(
        Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=provider-readiness-e2e-ca",
                "-keyout",
            ])
            .arg(&ca_key)
            .arg("-out")
            .arg(&ca),
        "generate fixture CA",
    )
    .await?;
    checked_command(
        Command::new("openssl")
            .args([
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                &format!("/CN={host}"),
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&csr),
        "generate fixture TLS key",
    )
    .await?;
    checked_command(
        Command::new("openssl")
            .args(["x509", "-req", "-days", "1", "-in"])
            .arg(&csr)
            .arg("-CA")
            .arg(&ca)
            .arg("-CAkey")
            .arg(&ca_key)
            .arg("-CAcreateserial")
            .arg("-extfile")
            .arg(&extensions)
            .arg("-out")
            .arg(&certificate),
        "sign fixture TLS certificate",
    )
    .await?;
    Ok((certificate, key))
}

async fn base_binaries(base: &str) -> Result<Value, String> {
    let engine = ContainerEngine::from_env()?;
    let name = format!(
        "e2e-readiness-binaries-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
        .map_err(|_| "binary probe requires the managed Docker namespace")?;
    let namespace_label = format!("openshell.ai/sandbox-namespace={namespace}");
    let mut command = Command::from(engine.command());
    command.args([
        "run", "--rm", "--name", &name, "--network", "none",
        "--label", "openshell.ai/managed-by=openshell",
        "--label", &namespace_label,
        "--label", "openshell.ai/isolation-role=fixture",
        "--entrypoint", "/usr/bin/python3", base,
        "-c", "import json,os,shutil,sys; print(json.dumps({'python':os.path.realpath(sys.executable),'curl':shutil.which('curl')}))",
    ]);
    // A timeout terminates the attached CLI, which does not prove its container
    // stopped. Always remove the known name; labels also let wrapper teardown
    // recover it if the entire test is cancelled before explicit cleanup.
    let result = async {
        let output = checked_command(&mut command, "inspect fixture image binaries").await?;
        let binaries: Value =
            serde_json::from_str(&output).map_err(|_| "image binary probe was invalid")?;
        for field in ["python", "curl"] {
            if !binaries[field]
                .as_str()
                .is_some_and(|path| Path::new(path).is_absolute())
            {
                return Err(format!("fixture image has no absolute {field} executable"));
            }
        }
        Ok(binaries)
    }
    .await;
    let cleanup = remove_fixture_container(&engine, &name).await;
    match (result, cleanup) {
        (Ok(binaries), Ok(())) => Ok(binaries),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; {cleanup}")),
    }
}

async fn remove_fixture_container(engine: &ContainerEngine, name: &str) -> Result<(), String> {
    let mut remove = Command::from(engine.command());
    remove.args(["rm", "--force", name]);
    let removed = checked_command(&mut remove, "remove fixture container").await;
    // --rm may have already removed a normally exited fixture. Only a
    // successful exact-name listing can establish absence after rm fails.
    if removed.is_err() {
        let mut list = Command::from(engine.command());
        let filter = format!("name=^/{name}$");
        list.args(["ps", "--all", "--quiet", "--filter", &filter]);
        if !checked_command(&mut list, "verify fixture container removal")
            .await?
            .trim()
            .is_empty()
        {
            return Err("fixture container remained after teardown".to_string());
        }
    }
    Ok(())
}

fn write_profile(
    path: &Path,
    name: &str,
    host: &str,
    port: u16,
    python: &str,
) -> Result<(), String> {
    let document = json!({
        "id": name, "display_name": "Provider readiness E2E", "category": "other",
        "credentials": [{"name": "synthetic", "env_vars": [TOKEN_ENV], "required": true,
            "auth_style": "bearer", "header_name": "authorization"}],
        "endpoints": [{"host": host, "port": port, "path": "/v1/**", "protocol": "rest",
            "access": "full", "enforcement": "enforce",
            "allowed_ips": [host]}],
        "binaries": [python],
    });
    std::fs::write(path, document.to_string())
        .map_err(|_| "could not write synthetic profile".to_string())
}

fn write_policy(
    path: &Path,
    host: &str,
    other_host: &str,
    port: u16,
    other_port: u16,
    python: &str,
) -> Result<(), String> {
    // Permit the negative endpoint probes at the network layer so the
    // credential binding itself must prevent them from reaching the backend.
    // The exact binary allowlist independently denies curl at the valid endpoint.
    let endpoints = [(host, port), (host, other_port), (other_host, port)]
        .into_iter()
        .map(|(host, port)| {
            json!({"host": host, "port": port, "path": "/**", "protocol": "rest",
            "access": "full", "enforcement": "enforce",
            "allowed_ips": [host]})
        })
        .collect::<Vec<_>>();
    let document = json!({
        "version": 1,
        "filesystem_policy": {"include_workdir": false,
            "read_only": ["/usr", "/lib", "/proc", "/dev/urandom", "/etc", "/opt", "/var/log"],
            "read_write": ["/sandbox", "/tmp", "/dev/null"]},
        "landlock": {"compatibility": "best_effort"},
        "process": {"run_as_user": "sandbox", "run_as_group": "sandbox"},
        "network_policies": {"synthetic_backend": {"name": "synthetic_backend",
            "endpoints": endpoints, "binaries": [{"path": python}]}},
    });
    std::fs::write(path, document.to_string())
        .map_err(|_| "could not write synthetic policy".to_string())
}

struct MutationReceipt {
    mutation_id: String,
    receipt: Value,
}

fn readiness_output(output: &str, keys: &[String; 2]) -> Result<Value, String> {
    // Never echo a malformed response: both a key leak and a leaked issued
    // reference must fail with the same fixed diagnostic.
    if keys.iter().any(|key| output.contains(key))
        || output.contains("openshell:resolve:")
        || output.contains("Bearer ")
    {
        return Err("provider readiness output contained credential material".to_string());
    }
    serde_json::from_str(output)
        .map_err(|_| "provider readiness output was invalid JSON".to_string())
}

fn single_target(body: &Value) -> Result<&Value, String> {
    let targets = body["targets"]
        .as_array()
        .ok_or("provider readiness targets were absent")?;
    // This provider is unique and has exactly one attachment. A mutation that
    // selects a different sandbox or omits this sandbox cannot satisfy the test.
    if targets.len() != 1 {
        return Err("provider readiness did not identify exactly one sandbox".to_string());
    }
    Ok(&targets[0])
}

fn nonempty_string<'a>(object: &'a Value, field: &str) -> Result<&'a str, String> {
    object[field]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("provider readiness identity field {field} was absent"))
}

impl MutationReceipt {
    fn capture(
        output: &str,
        sandbox: &SandboxGuard,
        provider: &str,
        kind: &str,
        keys: &[String; 2],
    ) -> Result<Self, String> {
        let body = readiness_output(output, keys)?;
        let status = single_target(&body)?;
        let receipt = &status["receipt"];
        let desired = &receipt["desired"];
        let mutation_id = nonempty_string(&body, "mutation_id")?;
        if receipt["mutation_id"] != mutation_id
            || receipt["provider_name"] != provider
            || receipt["kind"] != kind
            || desired["sandbox"] != sandbox.name
            || status["state"] != "persisted"
            || status["wait_outcome"] != "not_requested"
        {
            return Err(
                "provider mutation receipt did not match persisted target intent".to_string(),
            );
        }
        nonempty_string(receipt, "receipt_id")?;
        for field in [
            "sandbox_id",
            "attachment_epoch",
            "provider_resource_version",
            "provider_env_revision",
            "config_revision",
            "policy_hash",
        ] {
            nonempty_string(desired, field)?;
        }
        if kind == "detach" {
            if desired["provider_id"] != "" || desired["provider_resource_version"] != "0" {
                return Err("detach receipt retained provider authority".to_string());
            }
        } else {
            nonempty_string(desired, "provider_id")?;
        }
        nonempty_string(receipt, "persisted_time")?;
        Ok(Self {
            mutation_id: mutation_id.to_string(),
            receipt: receipt.clone(),
        })
    }

    fn follows(&self, previous: &Self) -> Result<(), String> {
        let desired = &self.receipt["desired"];
        let preceding = &previous.receipt["desired"];
        if self.mutation_id == previous.mutation_id
            || self.receipt["receipt_id"] == previous.receipt["receipt_id"]
            || self.receipt["provider_name"] != previous.receipt["provider_name"]
            || self.receipt["workspace"] != previous.receipt["workspace"]
            || desired["sandbox_id"] != preceding["sandbox_id"]
            || desired["sandbox"] != preceding["sandbox"]
            || desired["provider_env_revision"] == preceding["provider_env_revision"]
        {
            return Err(
                "provider mutation did not identify distinct authority for the same target"
                    .to_string(),
            );
        }
        // Revisions are opaque strings. Only identity equality is meaningful;
        // a numerically lower fingerprint is still a different installation.
        if self.receipt["kind"] == "update"
            && (desired["provider_id"] != preceding["provider_id"]
                || desired["provider_resource_version"] == preceding["provider_resource_version"]
                || desired["attachment_epoch"] != preceding["attachment_epoch"])
        {
            return Err("provider update did not preserve its attachment identity".to_string());
        }
        if self.receipt["kind"] == "detach"
            && desired["attachment_epoch"] == preceding["attachment_epoch"]
        {
            return Err("provider detach did not replace its attachment epoch".to_string());
        }
        Ok(())
    }

    async fn wait(
        &self,
        sandbox: &SandboxGuard,
        provider: &str,
        expected_state: &str,
        keys: &[String; 2],
    ) -> Result<Value, String> {
        let mut command = openshell_cmd();
        command.args([
            "sandbox",
            "provider",
            "status",
            &sandbox.name,
            provider,
            "--receipt",
            nonempty_string(&self.receipt, "receipt_id")?,
            "--wait",
            "--timeout",
            READINESS_TIMEOUT_SECONDS,
            "-o",
            "json",
        ]);
        let output = checked_command_with_timeout(
            &mut command,
            "wait for original provider mutation receipt",
            READINESS_COMMAND_TIMEOUT,
        )
        .await?;
        let body = readiness_output(&output, keys)?;
        let status = single_target(&body)?;
        if body["mutation_id"] != self.mutation_id
            || status["receipt"] != self.receipt
            || status["state"] != expected_state
            || status["reason"] != "unspecified"
            || status["wait_outcome"] != "complete"
        {
            return Err(
                "original provider receipt did not complete against its exact desired authority"
                    .to_string(),
            );
        }
        let desired = &self.receipt["desired"];
        let observed = &status["observed"];
        for field in [
            "attachment_epoch",
            "provider_env_revision",
            "config_revision",
            "policy_hash",
        ] {
            if observed[field] != desired[field] {
                return Err(format!(
                    "provider installation did not match desired {field}"
                ));
            }
        }
        for field in [
            "credentials_installed",
            "policy_active",
            "launch_environment_installed",
        ] {
            if observed[field] != true {
                return Err(format!("provider receipt completed without {field}"));
            }
        }
        for field in ["session_id", "sequence", "process_instance_id"] {
            nonempty_string(observed, field)?;
        }
        nonempty_string(status, "network_instance_id")?;
        nonempty_string(status, "observed_time")?;
        nonempty_string(status, "evaluated_time")?;
        if observed["reason"] != "unspecified" {
            return Err(
                "provider installation observation lacked a successful timestamped acknowledgment"
                    .to_string(),
            );
        }
        Ok(status.clone())
    }
}

async fn future_environment(
    sandbox: &SandboxGuard,
    python: &str,
    expected_present: bool,
) -> Result<(), String> {
    // A new exec consumes the process supervisor's current launch snapshot.
    // Only booleans leave the process, never the reference or its length.
    let script = "import json,os,re; key='PROVIDER_READINESS_E2E_TOKEN'; value=os.environ.get(key,''); print(json.dumps({'present':key in os.environ,'reference':bool(re.fullmatch(r'openshell:resolve:env:v[1-9][0-9]*_'+key,value))}))";
    let output = checked_command(
        &mut sandbox_command(sandbox, &[python, "-c", script]),
        "probe future process provider environment",
    )
    .await?;
    let result: Value =
        serde_json::from_str(output.trim()).map_err(|_| "future environment probe was invalid")?;
    if result["present"] != expected_present || result["reference"] != expected_present {
        return Err(
            "future process environment did not match acknowledged provider authority".to_string(),
        );
    }
    Ok(())
}

async fn probe(sandbox: &SandboxGuard, client: &str, phase: &str) -> Result<Value, String> {
    // Each retained process owns a separate mailbox so both old and current
    // references can be checked after detach without a client consuming the
    // other client's command. Labels and phases are fixed fixture constants.
    let control = format!("{CONTROL}-{client}");
    let result = format!("{RESULT}-{client}");
    // The client consumes the control file as soon as it appears. Publish a
    // complete phase atomically so polling cannot observe an empty write.
    let command = format!(
        "rm -f {result} && printf '%s' '{phase}' > {control}.tmp && mv {control}.tmp {control}"
    );
    checked_command(
        &mut sandbox_command(sandbox, &["sh", "-c", &command]),
        "trigger persistent client phase",
    )
    .await?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(output) = checked_command_with_timeout(
            &mut sandbox_command(sandbox, &["cat", &result]),
            "read persistent client phase",
            Duration::from_secs(10),
        )
        .await
        {
            let response: Value =
                serde_json::from_str(output.trim()).map_err(|_| "client result was invalid")?;
            if response["phase"] != phase || response["same_reference"] != true {
                return Err(
                    "persistent client changed its retained environment reference".to_string(),
                );
            }
            return Ok(response);
        }
        if Instant::now() >= deadline {
            return Err(format!("client phase {phase} did not finish"));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn probe_disallowed_binary(
    sandbox: &SandboxGuard,
    curl: &str,
    host: &str,
    port: u16,
) -> Result<(), String> {
    // Binary authorization includes allowed ancestors. Launch curl as a
    // sibling of the retained Python client, so Python cannot authorize it.
    // The shell builtin sends the reference only through curl's stdin pipe.
    let script = r#"
test -n "$PROVIDER_READINESS_E2E_TOKEN" || exit 64
"$1" --version >/dev/null 2>&1 || exit 65
if printf 'Authorization: Bearer %s\n' "$PROVIDER_READINESS_E2E_TOKEN" | \
    "$1" --silent --fail --max-time 5 --output /dev/null --header @- --data '{}' "$2" 2>/dev/null
then
    printf 'unexpected-success'
else
    printf 'denied'
fi
"#;
    let url = format!("https://{host}:{port}/v1/chat/completions");
    let output = checked_command(
        &mut sandbox_command(sandbox, &["sh", "-c", script, "binary-probe", curl, &url]),
        "probe independent disallowed binary",
    )
    .await?;
    if output.trim() != "denied" {
        return Err("independent disallowed binary reached the endpoint".to_string());
    }
    Ok(())
}

fn check(
    response: &Value,
    pid: u64,
    success: bool,
    backend_phase: Option<u64>,
) -> Result<(), String> {
    if response["pid"].as_u64() != Some(pid) || response["ok"].as_bool() != Some(success) {
        // Report only typed status fields; never include HTTP error text or
        // a serialized response that might later grow a credential field.
        return Err(format!(
            "client probe failed: pid_matches={}, expected_ok={success}, actual_ok={:?}, status={:?}, error_kind={:?}, reason_kind={:?}",
            response["pid"].as_u64() == Some(pid),
            response["ok"].as_bool(),
            response["status"].as_u64(),
            response["error_kind"].as_str(),
            response["reason_kind"].as_str(),
        ));
    }
    if let Some(phase) = backend_phase
        && (response["backend_phase"].as_u64() != Some(phase) || response["status"] != 200)
    {
        return Err("backend did not attest the expected credential generation".to_string());
    }
    Ok(())
}

#[tokio::test]
// Both clients remain alive through detach so their own retained references
// prove revocation across the attach and update launch boundaries.
#[allow(clippy::too_many_lines)]
async fn acknowledged_provider_changes_apply_to_fresh_clients_and_revoke_retained_references()
-> Result<(), String> {
    let mut gateway_config = GatewayTrustConfig::load()?;
    // Sandbox names are limited to 19 characters. Retain all 64 random bits
    // within that limit so concurrent fixtures still own distinct resources.
    let name = format!("e2e{:016x}", rand::random::<u64>());
    let mut backend = BackendPair::new(&name)?;
    // The wrapper's directory is shared with the host Docker daemon in CI;
    // a job-container-local temporary path cannot back the TLS bind mount.
    let fixture_parent = gateway_config
        .path
        .parent()
        .ok_or("managed gateway configuration has no parent directory")?;
    let directory =
        TempDir::new_in(fixture_parent).map_err(|_| "could not allocate fixture directory")?;
    let context = directory.path().join("image");
    std::fs::create_dir(&context).map_err(|_| "could not allocate public image context")?;
    let backend_tls = directory.path().join("backend-tls");
    std::fs::create_dir(&backend_tls).map_err(|_| "could not allocate backend TLS directory")?;
    let base = std::env::var("OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/nvidia/openshell-community/sandboxes/base:latest".to_string());
    if base.chars().any(char::is_whitespace) {
        return Err("fixture image reference contains whitespace".to_string());
    }
    let binaries = base_binaries(&base).await?;
    let python = binaries["python"]
        .as_str()
        .ok_or("Python executable was absent")?;
    let curl = binaries["curl"]
        .as_str()
        .ok_or("curl executable was absent")?;
    let image = FixtureImage::new()?;
    let supervisor_image = FixtureImage::new()?;
    // Each backend has its own network namespace, so fixed internal ports need
    // no host reservation or publication and remain independent across runs.
    let port = BACKEND_PORT;
    let other_port = OTHER_BACKEND_PORT;
    let keys = [
        format!("e2e-{:032x}", rand::random::<u128>()),
        format!("e2e-{:032x}", rand::random::<u128>()),
    ];
    let mut sandbox = None;
    let mut sandbox_attempted = false;
    let mut clients = Vec::with_capacity(2);
    let result = async {
        // Begin container mutation inside this scope so certificate, image,
        // and enrollment failures still reach explicit bounded teardown.
        let [host, other_host] = backend.spawn(&base, &backend_tls).await?;
        let (certificate, private_key) =
            generate_certificates(directory.path(), &host, &other_host).await?;
        std::fs::copy(&certificate, backend_tls.join("backend.crt"))
            .map_err(|_| "could not stage backend certificate")?;
        let backend_tls_key = backend_tls.join("backend.key.fixture");
        std::fs::copy(&private_key, &backend_tls_key)
            .map_err(|_| "could not stage backend TLS key")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // The backends inherit the image's unprivileged user. Only their
            // mounted leaf key is readable there; the host TempDir is private
            // and the CA signing key never enters a container or image context.
            std::fs::set_permissions(&backend_tls_key, std::fs::Permissions::from_mode(0o444))
                .map_err(|_| "could not set backend TLS key permissions")?;
        }
        backend.initialize(&json!({"keys": keys, "ports": [port, other_port],
            "certificate": "/fixture-tls/backend.crt", "private_key": "/fixture-tls/backend.key.fixture"}))
            .await?;
        std::fs::copy(directory.path().join("ca.crt"), context.join("fixture-ca.crt"))
            .map_err(|_| "could not copy public fixture CA")?;
        std::fs::write(context.join("client.py"), CLIENT)
            .map_err(|_| "could not write client source")?;
        let dockerfile = context.join("Dockerfile");
        std::fs::write(&dockerfile, format!(
            "FROM {base}\nUSER root\nCOPY client.py /opt/provider-readiness-client.py\nUSER sandbox\n"
        )).map_err(|_| "could not write fixture Dockerfile")?;
        let supervisor_dockerfile = context.join("Dockerfile.supervisor");
        // Outbound TLS belongs to the separate supervisor. Assemble its combined
        // public trust bundle in the shell-capable workload image because the
        // final supervisor image is intentionally distroless. Preserve the final
        // image's user setting: Docker's archive upload applies an explicit image
        // user to the supervisor's private bootstrap files.
        std::fs::write(&supervisor_dockerfile, format!(
            "FROM {} AS supervisor\nFROM {base} AS trust-bundle\nUSER 0\nCOPY --from=supervisor /etc/ssl/certs/ca-certificates.crt /tmp/ca-certificates.crt\nCOPY fixture-ca.crt /tmp/readiness-fixture-ca.crt\nRUN [\"/usr/bin/python3\", \"-c\", \"from pathlib import Path; bundle = Path('/tmp/ca-certificates.crt'); bundle.write_bytes(bundle.read_bytes() + Path('/tmp/readiness-fixture-ca.crt').read_bytes())\"]\nFROM {}\nCOPY --from=trust-bundle /tmp/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n",
            gateway_config.supervisor_image,
            gateway_config.supervisor_image,
        )).map_err(|_| "could not write fixture supervisor Dockerfile")?;
        image
            .build(&dockerfile, &context, "build workload fixture image")
            .await?;
        supervisor_image
            .build(
                &supervisor_dockerfile,
                &context,
                "build supervisor fixture image",
            )
            .await?;
        gateway_config.apply(supervisor_image.tag()).await?;
        let profile = directory.path().join("profile.json");
        let policy = directory.path().join("policy.json");
        write_profile(&profile, &name, &host, port, python)?;
        write_policy(&policy, &host, &other_host, port, other_port, python)?;
        let profile_path = profile.to_str().ok_or("profile path was not UTF-8")?;
        let policy_path = policy.to_str().ok_or("policy path was not UTF-8")?;
        let configuration = json!({"host": host, "other_host": other_host, "port": port,
            "other_port": other_port}).to_string();
        cli(
            "import synthetic provider profile",
            &["provider", "profile", "import", "--file", profile_path],
            None,
        )
        .await?;
        cli(
            "create synthetic provider",
            &[
                "provider",
                "create",
                "--name",
                &name,
                "--type",
                &name,
                "--credential",
                TOKEN_ENV,
            ],
            Some(&keys[0]),
        )
        .await?;
        // Retain a known name even when creation times out after persistence,
        // so teardown can still remove the partially created sandbox.
        sandbox_attempted = true;
        sandbox = Some(
            SandboxGuard::create(&[
                "--name",
                &name,
                "--from",
                image.tag(),
                "--policy",
                policy_path,
                "--no-auto-providers",
            ])
            .await
            .map_err(|_| "scratch sandbox could not start")?,
        );
        let running = sandbox
            .as_ref()
            .ok_or("sandbox was absent after creation")?;
        future_environment(running, python, false).await?;
        let output = cli(
            "attach synthetic provider",
            &[
                "sandbox",
                "provider",
                "attach",
                &running.name,
                &name,
                "-o",
                "json",
            ],
            None,
        )
        .await?;
        let attach = MutationReceipt::capture(&output, running, &name, "attach", &keys)?;
        let attached = attach.wait(running, &name, "ready", &keys).await?;
        future_environment(running, python, true).await?;
        // Start A only after the actual launch environment acknowledgment.
        // It retains this static reference until teardown; updates need not
        // change the credential selected by an already-running process.
        clients.push(PersistentClient::start(running, python, &configuration, "a").await?);
        let initial = probe(running, "a", "initial").await?;
        let pid_a = initial["pid"].as_u64().ok_or("client A PID was absent")?;
        check(&initial, pid_a, true, Some(0))?;
        let before = backend.counts().await?;
        if before["total"] != 1 || before["accepted"][0] != 1 {
            return Err("initial backend request count was incorrect".to_string());
        }
        for phase in [
            "wrong_host_control",
            "wrong_port_control",
            "wrong_path_control",
        ] {
            let control = probe(running, "a", phase).await?;
            check(&control, pid_a, false, None)?;
            if control["status"] != 401 || control["backend_phase"] != 0 {
                return Err(format!(
                    "negative endpoint {phase} was not reachable without a credential"
                ));
            }
        }
        let before = backend.counts().await?;
        if before["total"] != 4 || before["rejected"] != 3 || before["accepted"] != json!([1, 0]) {
            return Err("uncredentialed endpoint control assertions failed".to_string());
        }
        for phase in [
            "wrong_host",
            "wrong_port",
            "wrong_path",
            "untrusted_ca",
        ] {
            check(&probe(running, "a", phase).await?, pid_a, false, None)?;
            if backend.counts().await? != before {
                return Err(format!("denied phase {phase} reached the backend"));
            }
        }
        probe_disallowed_binary(running, curl, &host, port).await?;
        if backend.counts().await? != before {
            return Err("disallowed binary reached the backend".to_string());
        }

        backend.rotate().await?;
        let output = cli(
            "update synthetic provider once",
            &[
                "provider",
                "update",
                &name,
                "--credential",
                TOKEN_ENV,
                "-o",
                "json",
            ],
            Some(&keys[1]),
        )
        .await?;
        let update = MutationReceipt::capture(&output, running, &name, "update", &keys)?;
        update.follows(&attach)?;
        // No workload requests occur while waiting. Launch B through the
        // acknowledged environment boundary; its first request must use the
        // new credential without warming requests or success retries.
        let updated = update.wait(running, &name, "ready", &keys).await?;
        future_environment(running, python, true).await?;
        clients.push(PersistentClient::start(running, python, &configuration, "b").await?);
        let rotated_request = probe(running, "b", "rotated").await?;
        let pid_b = rotated_request["pid"].as_u64().ok_or("client B PID was absent")?;
        if pid_b == pid_a {
            return Err("provider update reused the original client process".to_string());
        }
        check(&rotated_request, pid_b, true, Some(1))?;
        let rotated = backend.counts().await?;
        if rotated["total"] != 5 || rotated["accepted"] != json!([1, 1]) || rotated["rejected"] != 3
        {
            return Err("single-update backend assertions failed".to_string());
        }

        let output = cli(
            "detach synthetic provider",
            &[
                "sandbox",
                "provider",
                "detach",
                &running.name,
                &name,
                "-o",
                "json",
            ],
            None,
        )
        .await?;
        let detach = MutationReceipt::capture(&output, running, &name, "detach", &keys)?;
        detach.follows(&update)?;
        let revoked = detach.wait(running, &name, "revoked", &keys).await?;
        future_environment(running, python, false).await?;
        // Detach must revoke the reference while leaving the independently
        // authorized route usable; a network outage cannot satisfy this proof.
        let control = probe(running, "b", "detached_control").await?;
        check(&control, pid_b, false, None)?;
        if control["status"] != 401 || control["backend_phase"] != 1 {
            return Err("detached endpoint was not reachable without a credential".to_string());
        }
        let detached = backend.counts().await?;
        if detached["total"] != 6
            || detached["accepted"] != json!([1, 1])
            || detached["rejected"] != 4
            || detached["phase"] != 1
        {
            return Err("detached endpoint control assertions failed".to_string());
        }
        for (client, pid) in [("a", pid_a), ("b", pid_b)] {
            check(&probe(running, client, "detached").await?, pid, false, None)?;
            if backend.counts().await? != detached {
                return Err(format!("detached client {client} credential reached the backend"));
            }
        }
        println!(
            "{}",
            json!({"phase": "complete", "client_a_pid": pid_a, "client_b_pid": pid_b,
            "clients_retained_own_references": true, "fresh_client_first_request_rotated": true,
            "endpoint_denials": true, "binary_denial": true,
            "tls_verified": true, "both_client_references_revoked": true,
            "future_environment_installed": true, "future_environment_removed": true,
            "attach": attached, "update": updated, "detach": revoked})
        );
        Ok(())
    }
    .await;

    // Resource names are unique to this run. Always attempt cleanup, including
    // failures during enrollment, and keep failures visible without exposing
    // captured provider output. The generic guard suppresses delete errors, so
    // first issue an explicit checked delete before disarming its fallback.
    let mut cleanup_results = Vec::new();
    if sandbox_attempted {
        cleanup_results.push(
            cli(
                "delete fixture sandbox",
                &["sandbox", "delete", &name],
                None,
            )
            .await
            .map(|_| ()),
        );
    }
    if let Some(mut sandbox) = sandbox {
        cleanup_results.push(
            timeout(COMMAND_TIMEOUT, sandbox.cleanup())
                .await
                .map_err(|_| "sandbox guard cleanup timed out".to_string()),
        );
    }
    for mut client in clients {
        cleanup_results.push(client.stop().await);
    }
    cleanup_results.push(
        cli(
            "delete synthetic provider",
            &["provider", "delete", &name],
            None,
        )
        .await
        .map(|_| ()),
    );
    cleanup_results.push(
        cli(
            "delete synthetic profile",
            &["provider", "profile", "delete", &name],
            None,
        )
        .await
        .map(|_| ()),
    );
    cleanup_results.push(backend.stop().await);
    // Restore the original runtime before removing its replacement. Retain the
    // derived supervisor image if restoration fails, and report that failure
    // even when a lifecycle assertion already failed.
    let gateway_restore = gateway_config.restore().await;
    let supervisor_cleanup = if gateway_restore.is_ok() {
        supervisor_image.remove().await
    } else {
        Ok(())
    };
    let image_cleanup = image.remove().await;
    let failures = [result, gateway_restore, supervisor_cleanup, image_cleanup]
        .into_iter()
        .chain(cleanup_results)
        .filter_map(Result::err)
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
