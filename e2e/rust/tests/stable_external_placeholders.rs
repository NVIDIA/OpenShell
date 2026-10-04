// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! External caller assertion rotation through a real sandbox HTTPS request path.
//!
//! The workload sends a synthetic `tools/call` request using one retained
//! supervisor-issued reference in one Python process. The fixture exercises
//! credential substitution, not a complete MCP session or an agent runtime.
//! Only the isolated backend and privileged provider CLI receive synthetic keys;
//! workload files, responses, and diagnostics contain status information only.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_network_name};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, SandboxGuard};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::time::{Instant, sleep, timeout};

const TOKEN_ENV: &str = "STABLE_EXTERNAL_E2E_TOKEN";
const BACKEND_PORT: u16 = 8443;
const OTHER_BACKEND_PORT: u16 = 8444;
const READY: &str = "stable-placeholder-client-ready";
const CONTROL: &str = "/sandbox/stable-placeholder-probe";
const RESULT: &str = "/sandbox/stable-placeholder-result";
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
const IMAGE_BUILD_TIMEOUT: Duration = Duration::from_secs(300);
const READINESS_TIMEOUT_SECONDS: &str = "90";
const READINESS_COMMAND_TIMEOUT: Duration = Duration::from_secs(105);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(120);

// Keys arrive on a private stdin pipe after process creation. Neither the
// command line nor any file contains them, and HTTP/server errors are silent.
const BACKEND: &str = r"
import http.server, json, ssl, sys, threading

sys.excepthook = lambda *_: None
config = json.loads(sys.stdin.readline())
keys = config.pop('keys')
lock = threading.Lock()
state = {'phase': 0, 'total': 0, 'accepted': [0, 0], 'rejected': 0,
         'received': [0, 0], 'missing': 0, 'unknown': 0, 'invalid_tool_calls': 0}

class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def handle_error(self, request, client_address):
        pass

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers.get('Content-Length', '0'))))
        tool_call = (request.get('jsonrpc') == '2.0' and request.get('method') == 'tools/call'
                     and request.get('params') == {'name': 'local_hello',
                                                   'arguments': {'name': 'rotation-proof'}})
        with lock:
            phase = state['phase']
            assertion = self.headers.get('x-openshell-sandbox-assertion')
            generation = 'missing' if assertion is None else 'unknown'
            for index, key in enumerate(keys):
                if assertion == key:
                    generation = 'A' if index == 0 else 'B'
                    state['received'][index] += 1
            if generation in ('missing', 'unknown'):
                state[generation] += 1
            if not tool_call:
                state['invalid_tool_calls'] += 1
            valid = assertion == keys[phase] and tool_call
            state['total'] += 1
            if valid:
                state['accepted'][phase] += 1
            else:
                state['rejected'] += 1
        response = {'jsonrpc': '2.0', 'id': request.get('id'),
                    'fixture': {'authorized': valid, 'phase': phase,
                                'credential_generation': generation, 'tool_call': tool_call}}
        if valid:
            response['result'] = {'content': [{'type': 'text', 'text': 'Hello rotation-proof'}]}
        else:
            response['error'] = {'code': -32001, 'message': 'Unauthorized'}
        body = json.dumps(response).encode()
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
key = 'STABLE_EXTERNAL_E2E_TOKEN'
token = os.environ.get(key, '')
pattern = r's[0-9a-f]{64}' if config['stable'] else r'v[1-9][0-9]*'
if not re.fullmatch(r'openshell:resolve:env:' + pattern + '_' + key, token):
    print('client did not receive the expected issued reference', flush=True)
    sys.exit(64)
pid = os.getpid()
control = pathlib.Path('/sandbox/stable-placeholder-probe')
result = pathlib.Path('/sandbox/stable-placeholder-result')

def probe(phase):
    host, port, path = config['host'], config['port'], '/mcp/local-hello'
    authorization = token
    target = phase[:-8] if phase.endswith('_control') else phase
    if target == 'wrong_host':
        host = config['other_host']
    elif target == 'wrong_port':
        port = config['other_port']
    elif target == 'wrong_path':
        path = '/outside'
    elif phase == 'canonical_alias':
        authorization = 'openshell:resolve:env:' + key
    url = 'https://%s:%s%s' % (host, port, path)
    response = {'phase': phase, 'pid': pid, 'same_reference': os.environ.get(key) == token,
                'ok': False, 'status': 0, 'backend_phase': -1,
                'credential_generation': 'unobserved', 'tool_call': False}
    try:
        context = ssl.create_default_context()
        if phase == 'untrusted_ca':
            # An empty trust store proves this client does verify TLS.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        headers = {'Content-Type': 'application/json'}
        if not phase.endswith('_control'):
            headers['x-openshell-sandbox-assertion'] = authorization
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                   'params': {'name': 'local_hello', 'arguments': {'name': 'rotation-proof'}}}
        request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
        try:
            reply = urllib.request.urlopen(request, context=context, timeout=5)
        except urllib.error.HTTPError as error:
            # The backend's safe 401 body proves the negative endpoint is
            # reachable before a credential-bearing request is denied.
            reply = error
        with reply:
            body = json.loads(reply.read(1024))
            attestation = body.get('fixture', {})
            response['ok'] = (attestation.get('authorized') is True
                              and body.get('result', {}).get('content') ==
                              [{'type': 'text', 'text': 'Hello rotation-proof'}])
            response['status'] = reply.status
            response['backend_phase'] = attestation.get('phase', -1)
            response['credential_generation'] = attestation.get('credential_generation', 'unobserved')
            response['tool_call'] = attestation.get('tool_call') is True
    except Exception as error:
        # HTTP/TLS exception text can embed headers. Type names expose the
        # failure layer without retaining messages, headers, or credentials.
        response['error_kind'] = type(error).__name__
        response['reason_kind'] = type(getattr(error, 'reason', None)).__name__
    return response

if len(sys.argv) > 2 and sys.argv[2] == '--once':
    print(json.dumps(probe('fresh')), flush=True)
    sys.exit(0)

print('stable-placeholder-client-ready', flush=True)
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
                "localhost/openshell-e2e-stable-{}-{:016x}:latest",
                std::process::id(),
                rand::random::<u64>(),
            ),
        })
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    async fn build(&self, dockerfile: &Path, context: &Path) -> Result<(), String> {
        let mut command = Command::from(self.engine.command());
        command
            .args(["build", "--file"])
            .arg(dockerfile)
            .args(["--tag", &self.tag])
            .arg(context);
        checked_command_with_timeout(&mut command, "build fixture image", IMAGE_BUILD_TIMEOUT)
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

// These tests run serially against a wrapper-owned gateway. The public fixture
// CA must be removed and the original supervisor restored before the next case.
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
            return Err("stable placeholder fixture requires a wrapper-owned gateway with the bundled Docker driver".to_string());
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
        // The host-networked supervisor cannot resolve Docker bridge aliases.
        // Python waits for configuration on stdin while we inspect its bridge
        // address and generate a certificate for that exact IP.
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
        let mut remove = Command::from(self.engine.command());
        remove.args(["rm", "--force", &self.name]);
        let removed = checked_command(&mut remove, "remove synthetic backend container").await;
        // --rm may have already removed a normally exited backend. Only a
        // successful exact-name listing can establish absence after rm fails.
        if removed.is_err() {
            let mut list = Command::from(self.engine.command());
            let filter = format!("name=^/{}$", self.name);
            list.args(["ps", "--all", "--quiet", "--filter", &filter]);
            if !checked_command(&mut list, "verify synthetic backend removal")
                .await?
                .trim()
                .is_empty()
            {
                return Err("synthetic backend container remained after teardown".to_string());
            }
        }
        reap_result
    }
}

// Counters attest generations without retaining headers or credential values.
#[derive(Deserialize, Serialize)]
struct BackendCounts {
    phase: u8,
    total: u64,
    accepted: [u64; 2],
    rejected: u64,
    received: [u64; 2],
    missing: u64,
    unknown: u64,
    invalid_tool_calls: u64,
}

// Distinct bridge addresses provide independent authorized and wrong-host
// endpoints. Summed counters prove denied traffic reaches neither container.
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
                return Err("backend did not switch to the replacement assertion".to_string());
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
                    return Err("fixture backends disagree on the active assertion".to_string());
                }
                let add = |left: u64, right: u64| {
                    left.checked_add(right).ok_or("backend counters overflowed")
                };
                total.total = add(total.total, counters.total)?;
                total.rejected = add(total.rejected, counters.rejected)?;
                total.missing = add(total.missing, counters.missing)?;
                total.unknown = add(total.unknown, counters.unknown)?;
                total.invalid_tool_calls =
                    add(total.invalid_tool_calls, counters.invalid_tool_calls)?;
                for (left, right) in total.accepted.iter_mut().zip(counters.accepted) {
                    *left = add(*left, right)?;
                }
                for (left, right) in total.received.iter_mut().zip(counters.received) {
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
                "/CN=stable-placeholder-e2e-ca",
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
    let mut command = Command::from(engine.command());
    command.args([
        "run", "--rm", "--network", "none", "--entrypoint", "/usr/bin/python3", base,
        "-c", "import json,os,shutil,sys; print(json.dumps({'python':os.path.realpath(sys.executable),'curl':shutil.which('curl')}))",
    ]);
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

fn write_profile(
    path: &Path,
    name: &str,
    host: &str,
    port: u16,
    python: &str,
    stable: bool,
) -> Result<(), String> {
    // Omitting the opt-in reproduces the behavior of an existing static
    // credential profile on both the upstream gateway and the candidate.
    let mut credential = json!({"name": "synthetic_assertion", "env_vars": [TOKEN_ENV],
        "required": true, "auth_style": "header", "header_name": "x-openshell-sandbox-assertion"});
    if stable {
        credential["stable_placeholder"] = json!(true);
    }
    let document = json!({
        "id": name, "display_name": "External caller assertion E2E", "category": "other",
        "credentials": [credential],
        "endpoints": [{"host": host, "port": port, "path": "/mcp/**", "protocol": "rest",
            "access": "full", "enforcement": "enforce",
            "allowed_ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]}],
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
            "allowed_ips": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]})
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

async fn acknowledged_mutation(
    args: &[&str],
    credential: Option<&str>,
    sandbox: &SandboxGuard,
    provider: &str,
    kind: &str,
    keys: &[String; 2],
) -> Result<(), String> {
    let mut command = openshell_cmd();
    command.args(args).args([
        "--wait",
        "--timeout",
        READINESS_TIMEOUT_SECONDS,
        "-o",
        "json",
    ]);
    if let Some(credential) = credential {
        command.env(TOKEN_ENV, credential);
    }
    let output = checked_command_with_timeout(
        &mut command,
        "apply and acknowledge provider mutation",
        READINESS_COMMAND_TIMEOUT,
    )
    .await?;
    if keys.iter().any(|key| output.contains(key)) || output.contains("openshell:resolve:") {
        return Err("provider readiness output contained credential material".to_string());
    }
    let body: Value =
        serde_json::from_str(&output).map_err(|_| "provider readiness output was invalid JSON")?;
    let targets = body["targets"]
        .as_array()
        .ok_or("provider readiness targets were absent")?;
    let [status] = targets.as_slice() else {
        return Err("provider mutation did not acknowledge exactly one sandbox".to_string());
    };
    let receipt = &status["receipt"];
    let desired = &receipt["desired"];
    let observed = &status["observed"];
    let expected = if kind == "detach" { "revoked" } else { "ready" };
    if body["mutation_id"].as_str().is_none_or(str::is_empty)
        || receipt["mutation_id"] != body["mutation_id"]
        || receipt["provider"] != provider
        || receipt["kind"] != kind
        || desired["sandbox"] != sandbox.name
        || status["state"] != expected
        || status["wait_outcome"] != "complete"
        || status["reason"] != "unspecified"
        || observed["reason"] != "unspecified"
    {
        return Err("provider mutation was not acknowledged for the intended sandbox".to_string());
    }
    for field in [
        "attachment_epoch",
        "provider_env_revision",
        "config_revision",
        "policy_hash",
    ] {
        if desired[field].as_str().is_none_or(str::is_empty) || observed[field] != desired[field] {
            return Err(format!(
                "provider acknowledgment did not match desired {field}"
            ));
        }
    }
    for field in [
        "credentials_installed",
        "policy_active",
        "launch_environment_installed",
    ] {
        if observed[field] != true {
            return Err(format!("provider acknowledgment omitted {field}"));
        }
    }
    Ok(())
}

async fn probe(sandbox: &SandboxGuard, phase: &str) -> Result<Value, String> {
    // The client consumes the control file as soon as it appears. Publish a
    // complete phase atomically so polling cannot observe an empty write.
    let command = format!(
        "rm -f {RESULT} && printf '%s' '{phase}' > {CONTROL}.tmp && mv {CONTROL}.tmp {CONTROL}"
    );
    timeout(COMMAND_TIMEOUT, sandbox.exec(&["sh", "-c", &command]))
        .await
        .map_err(|_| "client trigger timed out")?
        .map_err(|_| "client trigger failed")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(Ok(output)) =
            timeout(Duration::from_secs(10), sandbox.exec(&["cat", RESULT])).await
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
test -n "$STABLE_EXTERNAL_E2E_TOKEN" || exit 64
"$1" --version >/dev/null 2>&1 || exit 65
if printf 'x-openshell-sandbox-assertion: %s\n' "$STABLE_EXTERNAL_E2E_TOKEN" | \
    "$1" --silent --fail --max-time 5 --output /dev/null --header @- \
    --data '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"local_hello","arguments":{"name":"rotation-proof"}}}' "$2" 2>/dev/null
then
    printf 'unexpected-success'
else
    printf 'denied'
fi
"#;
    let url = format!("https://{host}:{port}/mcp/local-hello");
    let output = timeout(
        COMMAND_TIMEOUT,
        sandbox.exec(&["sh", "-c", script, "binary-probe", curl, &url]),
    )
    .await
    .map_err(|_| "independent binary probe timed out")?
    .map_err(|_| "independent binary probe failed to execute")?;
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
        && (response["backend_phase"].as_u64() != Some(phase)
            || response["status"] != 200
            || response["credential_generation"] != if phase == 0 { "A" } else { "B" }
            || response["tool_call"] != true)
    {
        return Err("backend did not attest the expected credential generation".to_string());
    }
    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn persistent_external_placeholder_rotation_and_revocation() -> Result<(), String> {
    external_caller_assertion_rotation(true).await
}

#[tokio::test]
#[serial_test::serial]
async fn ordinary_external_placeholder_keeps_revoked_assertion_after_rotation() -> Result<(), String>
{
    external_caller_assertion_rotation(false).await
}

// Keep each lifecycle together so no phase can replace the retained client.
#[allow(clippy::too_many_lines)]
async fn external_caller_assertion_rotation(stable: bool) -> Result<(), String> {
    let mut gateway_config = GatewayTrustConfig::load()?;
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
    std::fs::write(context.join("client.py"), CLIENT)
        .map_err(|_| "could not write client source")?;
    let base = std::env::var("OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE")
        .unwrap_or_else(|_| E2E_WORKLOAD_IMAGE.to_string());
    if base.chars().any(char::is_whitespace) {
        return Err("fixture image reference contains whitespace".to_string());
    }
    let binaries = base_binaries(&base).await?;
    let python = binaries["python"]
        .as_str()
        .ok_or("Python executable was absent")?;
    let dockerfile = context.join("Dockerfile");
    std::fs::write(
        &dockerfile,
        format!("FROM {base}\nCOPY client.py /opt/stable-placeholder-client.py\nUSER 1000:1000\n"),
    )
    .map_err(|_| "could not write fixture Dockerfile")?;
    let supervisor_dockerfile = context.join("Dockerfile.supervisor");
    // Build the combined trust bundle in the workload image: the supervisor is
    // distroless and has no shell. The final stage preserves the supervisor's
    // default user and its original public trust roots.
    std::fs::write(&supervisor_dockerfile, format!(
        "FROM {} AS supervisor\nFROM {base} AS trust-bundle\nUSER 0\nCOPY --from=supervisor /etc/ssl/certs/ca-certificates.crt /tmp/ca-certificates.crt\nCOPY fixture-ca.crt /tmp/stable-fixture-ca.crt\nRUN [\"/usr/bin/python3\", \"-c\", \"from pathlib import Path; bundle = Path('/tmp/ca-certificates.crt'); bundle.write_bytes(bundle.read_bytes() + Path('/tmp/stable-fixture-ca.crt').read_bytes())\"]\nFROM {}\nCOPY --from=trust-bundle /tmp/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\n",
        gateway_config.supervisor_image,
        gateway_config.supervisor_image
    )).map_err(|_| "could not write fixture supervisor Dockerfile")?;
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
    let profile = directory.path().join("profile.json");
    let policy = directory.path().join("policy.json");
    let profile_path = profile.to_str().ok_or("profile path was not UTF-8")?;
    let policy_path = policy.to_str().ok_or("policy path was not UTF-8")?;
    let curl = binaries["curl"]
        .as_str()
        .ok_or("curl executable was absent")?;
    let mut sandbox = None;
    let result = async {
        // Begin container mutation inside this scope so address, certificate,
        // image and enrollment failures all reach explicit bounded teardown.
        image.build(&dockerfile, &context).await?;
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
            // mounted leaf key is readable; the private CA key stays outside
            // the shared mount and both image build contexts.
            std::fs::set_permissions(&backend_tls_key, std::fs::Permissions::from_mode(0o444))
                .map_err(|_| "could not set backend TLS key permissions")?;
        }
        backend.initialize(&json!({"keys": keys, "ports": [port, other_port],
            "certificate": "/fixture-tls/backend.crt", "private_key": "/fixture-tls/backend.key.fixture"}))
            .await?;
        std::fs::copy(directory.path().join("ca.crt"), context.join("fixture-ca.crt"))
            .map_err(|_| "could not copy public fixture CA")?;
        supervisor_image
            .build(&supervisor_dockerfile, &context)
            .await?;
        gateway_config.apply(supervisor_image.tag()).await?;
        write_profile(&profile, &name, &host, port, python, stable)?;
        write_policy(&policy, &host, &other_host, port, other_port, python)?;
        let configuration = json!({"host": host, "other_host": other_host, "port": port,
            "other_port": other_port, "stable": stable}).to_string();
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
        sandbox = Some(
            SandboxGuard::create_keep_with_args(
                &[
                    "--from",
                    image.tag(),
                    "--provider",
                    &name,
                    "--policy",
                    policy_path,
                    "--no-auto-providers",
                ],
                &[
                    "/usr/bin/python3",
                    "-u",
                    "/opt/stable-placeholder-client.py",
                    &configuration,
                ],
                READY,
            )
            .await
            .map_err(|_| "persistent sandbox client could not start")?,
        );
        let running = sandbox
            .as_ref()
            .ok_or("sandbox was absent after creation")?;
        let initial = probe(running, "initial").await?;
        let pid = initial["pid"].as_u64().ok_or("client PID was absent")?;
        check(&initial, pid, true, Some(0))?;
        let before = backend.counts().await?;
        if before["total"] != 1 || before["accepted"][0] != 1 {
            return Err("initial backend request count was incorrect".to_string());
        }
        for phase in [
            "wrong_host_control",
            "wrong_port_control",
            "wrong_path_control",
        ] {
            let control = probe(running, phase).await?;
            check(&control, pid, false, None)?;
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
            "canonical_alias",
            "untrusted_ca",
        ] {
            check(&probe(running, phase).await?, pid, false, None)?;
            if backend.counts().await? != before {
                return Err(format!("denied phase {phase} reached the backend"));
            }
        }
        probe_disallowed_binary(running, curl, &host, port).await?;
        if backend.counts().await? != before {
            return Err("disallowed binary reached the backend".to_string());
        }

        backend.rotate().await?;
        // This is the only provider update. --wait acknowledges the exact
        // saved revision before either client sends its next tool request.
        acknowledged_mutation(
            &["provider", "update", &name, "--credential", TOKEN_ENV],
            Some(&keys[1]),
            running, &name, "update", &keys,
        )
        .await?;
        // No workload requests occur while waiting. The first next request
        // must use B with the opt-in; the ordinary profile still resolves A.
        let retained = probe(running, "rotated").await?;
        check(&retained, pid, stable, stable.then_some(1))?;
        if !stable && (retained["status"] != 401 || retained["backend_phase"] != 1
            || retained["credential_generation"] != "A" || retained["tool_call"] != true)
        {
            return Err("ordinary retained reference did not send the revoked assertion A".to_string());
        }
        let rotated = backend.counts().await?;
        let accepted_after_rotation = if stable { json!([1, 1]) } else { json!([1, 0]) };
        let received_after_rotation = if stable { json!([1, 1]) } else { json!([2, 0]) };
        let rejected_after_rotation = if stable { 3 } else { 4 };
        if rotated["total"] != 5 || rotated["accepted"] != accepted_after_rotation
            || rotated["received"] != received_after_rotation
            || rotated["rejected"] != rejected_after_rotation
            || rotated["missing"] != 3 || rotated["unknown"] != 0 || rotated["invalid_tool_calls"] != 0
        {
            return Err("single-update backend assertions failed".to_string());
        }

        // A fresh process proves the installed provider revision can use B in
        // both modes. It does not replace or modify the original client.
        let fresh_output = timeout(COMMAND_TIMEOUT, running.exec(&[
            "/usr/bin/python3", "-u", "/opt/stable-placeholder-client.py", &configuration, "--once",
        ])).await.map_err(|_| "fresh client timed out")?
            .map_err(|_| "fresh client failed")?;
        let fresh: Value = serde_json::from_str(fresh_output.trim())
            .map_err(|_| "fresh client returned invalid status")?;
        let fresh_pid = fresh["pid"].as_u64().ok_or("fresh client PID was absent")?;
        if fresh_pid == pid || fresh["same_reference"] != true {
            return Err("fresh process control did not retain its own issued reference".to_string());
        }
        check(&fresh, fresh_pid, true, Some(1))?;
        let refreshed = backend.counts().await?;
        let final_accepted = if stable { json!([1, 2]) } else { json!([1, 1]) };
        let final_received = if stable { json!([1, 2]) } else { json!([2, 1]) };
        if refreshed["total"] != 6 || refreshed["accepted"] != final_accepted
            || refreshed["received"] != final_received || refreshed["rejected"] != rejected_after_rotation
            || refreshed["missing"] != 3 || refreshed["unknown"] != 0 || refreshed["invalid_tool_calls"] != 0
        {
            return Err("fresh process did not prove installed assertion B".to_string());
        }

        acknowledged_mutation(
            &["sandbox", "provider", "detach", &running.name, &name],
            None,
            running, &name, "detach", &keys,
        )
        .await?;
        // Detach must revoke the reference while leaving the independently
        // authorized route usable; a network outage cannot satisfy this proof.
        let control = probe(running, "detached_control").await?;
        check(&control, pid, false, None)?;
        if control["status"] != 401 || control["backend_phase"] != 1 {
            return Err("detached endpoint was not reachable without a credential".to_string());
        }
        let detached = backend.counts().await?;
        if detached["total"] != 7
            || detached["accepted"] != final_accepted
            || detached["received"] != final_received
            || detached["rejected"] != rejected_after_rotation + 1
            || detached["missing"] != 4 || detached["unknown"] != 0 || detached["invalid_tool_calls"] != 0
            || detached["phase"] != 1
        {
            return Err("detached endpoint control assertions failed".to_string());
        }
        check(&probe(running, "detached").await?, pid, false, None)?;
        if backend.counts().await? != detached {
            return Err("detached credential reached the backend".to_string());
        }
        println!(
            "{}",
            json!({"phase": "complete", "pid": pid, "same_reference": true,
            "stable_placeholder": stable, "provider_updates": 1,
            "retained_assertion": if stable { "B" } else { "A" },
            "retained_request_accepted": stable, "fresh_process_assertion": "B",
            "tool": "local_hello", "endpoint_denials": true, "binary_denial": true,
            "canonical_alias_denial": true, "tls_verified": true, "detached": true})
        );
        Ok(())
    }
    .await;

    // Resource names are unique to this run. Always attempt cleanup, including
    // failures during enrollment, without exposing captured provider output.
    if let Some(mut sandbox) = sandbox {
        let _ = timeout(COMMAND_TIMEOUT, sandbox.cleanup()).await;
    }
    let _ = cli(
        "delete synthetic provider",
        &["provider", "delete", &name],
        None,
    )
    .await;
    let _ = cli(
        "delete synthetic profile",
        &["provider", "profile", "delete", &name],
        None,
    )
    .await;
    let backend_cleanup = backend.stop().await;
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
    let failures = [
        result,
        backend_cleanup,
        gateway_restore,
        supervisor_cleanup,
        image_cleanup,
    ]
    .into_iter()
    .filter_map(Result::err)
    .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
