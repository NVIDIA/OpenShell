// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! External credential rotation through a real sandbox HTTPS request path.
//!
//! The workload keeps one supervisor-issued reference in one Python process.
//! Only the isolated backend and privileged provider CLI receive synthetic keys;
//! workload files, responses, and diagnostics contain status information only.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::container::{ContainerEngine, e2e_network_name};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
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
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(90);
const GATEWAY_READY_TIMEOUT: Duration = Duration::from_secs(120);

// Keys arrive on a private stdin pipe after process creation. Neither the
// command line nor any file contains them, and HTTP/server errors are silent.
const BACKEND: &str = r"
import http.server, json, ssl, sys, threading

sys.excepthook = lambda *_: None
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
key = 'STABLE_EXTERNAL_E2E_TOKEN'
token = os.environ.get(key, '')
if not re.fullmatch(r'openshell:resolve:env:s[0-9a-f]{64}_' + key, token):
    print('client did not receive an identity-bound reference', flush=True)
    sys.exit(64)
pid = os.getpid()
control = pathlib.Path('/sandbox/stable-placeholder-probe')
result = pathlib.Path('/sandbox/stable-placeholder-result')

def probe(phase):
    host, port, path = config['host'], config['port'], '/v1/chat/completions'
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
                'ok': False, 'status': 0, 'backend_phase': -1}
    try:
        context = ssl.create_default_context()
        if phase == 'untrusted_ca':
            # An empty trust store proves this client does verify TLS.
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        headers = {'Content-Type': 'application/json'}
        if not phase.endswith('_control'):
            headers['Authorization'] = 'Bearer ' + authorization
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
        # HTTP/TLS exception text can embed headers. Type names expose the
        # failure layer without retaining messages, headers, or credentials.
        response['error_kind'] = type(error).__name__
        response['reason_kind'] = type(getattr(error, 'reason', None)).__name__
    return response

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
    hosts: [String; 2],
    child: Option<Child>,
    input: Option<ChildStdin>,
    output: Option<Lines<BufReader<ChildStdout>>>,
    launch_attempted: bool,
}

impl Backend {
    fn new(name: String, hosts: [String; 2]) -> Result<Self, String> {
        Ok(Self {
            engine: ContainerEngine::from_env()?,
            name,
            network: e2e_network_name().ok_or("fixture requires the managed Docker network")?,
            namespace: std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
                .map_err(|_| "fixture requires the managed Docker namespace")?,
            hosts,
            child: None,
            input: None,
            output: None,
            launch_attempted: false,
        })
    }

    async fn start(
        &mut self,
        base: &str,
        tls_directory: &Path,
        config: &Value,
    ) -> Result<(), String> {
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
                "--network-alias",
                &self.hosts[0],
                "--network-alias",
                &self.hosts[1],
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

    async fn counts(&mut self) -> Result<Value, String> {
        self.exchange(&json!({"command": "snapshot"})).await
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
            "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:{host},DNS:{other_host}\nextendedKeyUsage=serverAuth\n"
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
) -> Result<(), String> {
    let document = json!({
        "id": name, "display_name": "Stable external placeholder E2E", "category": "other",
        "credentials": [{"name": "synthetic", "env_vars": [TOKEN_ENV], "required": true,
            "auth_style": "bearer", "header_name": "authorization", "stable_placeholder": true}],
        "endpoints": [{"host": host, "port": port, "path": "/v1/**", "protocol": "rest",
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

async fn receipts(sandbox: &SandboxGuard) -> Result<HashSet<String>, String> {
    let logs = cli(
        "read supervisor activation receipts",
        &[
            "logs",
            &sandbox.name,
            "-n",
            "500",
            "--since",
            "10m",
            "--source",
            "sandbox",
        ],
        None,
    )
    .await?;
    Ok(logs
        .lines()
        .filter_map(|line| {
            let (_, suffix) = line.split_once("Provider environment refreshed [revision:")?;
            let revision: String = suffix.chars().take_while(char::is_ascii_digit).collect();
            (!revision.is_empty()).then_some(revision)
        })
        .collect())
}

async fn wait_for_activation(
    sandbox: &SandboxGuard,
    previous: &HashSet<String>,
) -> Result<(), String> {
    let deadline = Instant::now() + ACTIVATION_TIMEOUT;
    loop {
        if receipts(sandbox)
            .await?
            .iter()
            .any(|revision| !previous.contains(revision))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("supervisor did not acknowledge a new provider environment".to_string());
        }
        sleep(Duration::from_millis(250)).await;
    }
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
if printf 'Authorization: Bearer %s\n' "$STABLE_EXTERNAL_E2E_TOKEN" | \
    "$1" --silent --fail --max-time 5 --output /dev/null --header @- --data '{}' "$2" 2>/dev/null
then
    printf 'unexpected-success'
else
    printf 'denied'
fi
"#;
    let url = format!("https://{host}:{port}/v1/chat/completions");
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
        && (response["backend_phase"].as_u64() != Some(phase) || response["status"] != 200)
    {
        return Err("backend did not attest the expected credential generation".to_string());
    }
    Ok(())
}

#[tokio::test]
// Keep the lifecycle in one test so no phase can replace the retained client.
#[allow(clippy::too_many_lines)]
async fn persistent_external_placeholder_rotation_and_revocation() -> Result<(), String> {
    let mut gateway_config = GatewayTrustConfig::load()?;
    let name = format!(
        "e2e-stable-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    // Ordinary bridge DNS aliases exercise the policy DNS path without relying
    // on a host-gateway address outside the supervisor's container network.
    let host = format!("{name}.test");
    let other_host = format!("{name}-other.test");
    let mut backend = Backend::new(
        format!("{name}-backend"),
        [host.clone(), other_host.clone()],
    )?;
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
    let (certificate, private_key) =
        generate_certificates(directory.path(), &host, &other_host).await?;
    let backend_tls = directory.path().join("backend-tls");
    std::fs::create_dir(&backend_tls).map_err(|_| "could not allocate backend TLS directory")?;
    std::fs::copy(&certificate, backend_tls.join("backend.crt"))
        .map_err(|_| "could not stage backend certificate")?;
    let backend_tls_key = backend_tls.join("backend.key.fixture");
    std::fs::copy(&private_key, &backend_tls_key).map_err(|_| "could not stage backend TLS key")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        // The backend inherits the image's unprivileged user. Only its mounted
        // leaf key is readable there; the parent TempDir stays private and the
        // CA signing key never enters a container or either image build context.
        std::fs::set_permissions(&backend_tls_key, std::fs::Permissions::from_mode(0o444))
            .map_err(|_| "could not set backend TLS key permissions")?;
    }
    std::fs::copy(
        directory.path().join("ca.crt"),
        context.join("fixture-ca.crt"),
    )
    .map_err(|_| "could not copy public fixture CA")?;
    std::fs::write(context.join("client.py"), CLIENT)
        .map_err(|_| "could not write client source")?;
    let base = std::env::var("OPENSHELL_E2E_DOCKER_SANDBOX_IMAGE")
        .unwrap_or_else(|_| "ghcr.io/nvidia/openshell-community/sandboxes/base:latest".to_string());
    if base.chars().any(char::is_whitespace) {
        return Err("fixture image reference contains whitespace".to_string());
    }
    let binaries = base_binaries(&base).await?;
    let python = binaries["python"]
        .as_str()
        .ok_or("Python executable was absent")?;
    let dockerfile = context.join("Dockerfile");
    std::fs::write(&dockerfile, format!(
        "FROM {base}\nUSER root\nCOPY client.py /opt/stable-placeholder-client.py\nUSER sandbox\n"
    )).map_err(|_| "could not write fixture Dockerfile")?;
    let supervisor_dockerfile = context.join("Dockerfile.supervisor");
    // Outbound TLS belongs to the separate supervisor. Its combined public
    // trust bundle is delivered to the workload through the sandbox protocol.
    // Preserve the base image's user setting: Docker's archive upload applies
    // an explicit image user to the supervisor's private bootstrap files.
    std::fs::write(&supervisor_dockerfile, format!(
        "FROM {}\nCOPY fixture-ca.crt /tmp/stable-fixture-ca.crt\nRUN cat /tmp/stable-fixture-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/stable-fixture-ca.crt\n",
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
    write_profile(&profile, &name, &host, port, python)?;
    write_policy(&policy, &host, &other_host, port, other_port, python)?;
    let profile_path = profile.to_str().ok_or("profile path was not UTF-8")?;
    let policy_path = policy.to_str().ok_or("policy path was not UTF-8")?;
    let curl = binaries["curl"]
        .as_str()
        .ok_or("curl executable was absent")?;
    let configuration = json!({"host": host, "other_host": other_host, "port": port,
        "other_port": other_port})
    .to_string();
    let mut sandbox = None;
    let result = async {
        // Begin image mutation only inside this result scope so enrollment or
        // build failures still flow through the explicit bounded teardown.
        image.build(&dockerfile, &context).await?;
        supervisor_image
            .build(&supervisor_dockerfile, &context)
            .await?;
        gateway_config.apply(supervisor_image.tag()).await?;
        backend.start(&base, &backend_tls, &json!({"keys": keys, "ports": [port, other_port],
            "certificate": "/fixture-tls/backend.crt", "private_key": "/fixture-tls/backend.key.fixture"}))
            .await?;
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

        let previous = receipts(running).await?;
        backend.exchange(&json!({"command": "rotate"})).await?;
        cli(
            "update synthetic provider once",
            &["provider", "update", &name, "--credential", TOKEN_ENV],
            Some(&keys[1]),
        )
        .await?;
        // No workload requests occur while waiting. The first next request
        // therefore proves activation, rather than eventually succeeding by retry.
        wait_for_activation(running, &previous).await?;
        check(&probe(running, "rotated").await?, pid, true, Some(1))?;
        let rotated = backend.counts().await?;
        if rotated["total"] != 5 || rotated["accepted"] != json!([1, 1]) || rotated["rejected"] != 3
        {
            return Err("single-update backend assertions failed".to_string());
        }

        let previous = receipts(running).await?;
        cli(
            "detach synthetic provider",
            &["sandbox", "provider", "detach", &running.name, &name],
            None,
        )
        .await?;
        wait_for_activation(running, &previous).await?;
        // Detach must revoke the reference while leaving the independently
        // authorized route usable; a network outage cannot satisfy this proof.
        let control = probe(running, "detached_control").await?;
        check(&control, pid, false, None)?;
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
        check(&probe(running, "detached").await?, pid, false, None)?;
        if backend.counts().await? != detached {
            return Err("detached credential reached the backend".to_string());
        }
        println!(
            "{}",
            json!({"phase": "complete", "pid": pid, "same_reference": true,
            "rotated": true, "endpoint_denials": true, "binary_denial": true,
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
