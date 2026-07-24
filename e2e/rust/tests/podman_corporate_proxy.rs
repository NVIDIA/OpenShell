// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-podman")]

//! Cross-layer E2E coverage for corporate forward-proxy egress (issue #1792).
//!
//! Every other test for this feature builds a config struct or calls a CONNECT
//! helper directly, so none of them can catch a break in the wiring *between*
//! layers. This test drives the whole chain end to end:
//!
//! gateway TOML → Podman driver config → supervisor argv + secret mount →
//! supervisor CLI parsing → policy evaluation → proxied CONNECT
//!
//! against a fake authenticated forward proxy, and asserts the four properties
//! that only a real run can establish:
//!
//! 1. A policy-approved HTTPS request reaches its destination *through* the
//!    proxy, and the CONNECT target is a validated IP rather than a hostname.
//! 2. A policy-denied destination never reaches the proxy at all.
//! 3. Credentials arrive via the mounted Podman secret — the proxy answers 407
//!    to an unauthenticated CONNECT, so a 200 response proves delivery.
//! 4. Deleting the sandbox removes the per-sandbox Podman secret.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_healthy;
use openshell_e2e::harness::container::{ContainerEngine, SupportContainer};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const PROXY_ALIAS: &str = "corp-proxy.openshell.test";
const PROXY_PORT: u16 = 3128;
const ALLOWED_ALIAS: &str = "tls-upstream.openshell.test";
const DENIED_ALIAS: &str = "denied-upstream.openshell.test";
const UPSTREAM_PORT: u16 = 8443;

const PROXY_USER: &str = "proxyuser";
const PROXY_PASS: &str = "proxypass";

const ALLOWED_MARKER: &str = "corp-proxy-e2e-allowed-upstream";
const DENIED_MARKER: &str = "corp-proxy-e2e-denied-upstream";
const READY_MARKER: &str = "corp-proxy-e2e-workload-done";

const SECRET_PREFIX: &str = "openshell-proxy-auth-";

/// A forward proxy that requires Basic auth and logs every CONNECT it sees.
///
/// The log lines are the test's evidence: they record the exact CONNECT target
/// (proving validated-IP vs hostname form) and whether credentials arrived.
fn proxy_script() -> String {
    format!(
        r#"
import base64, select, socket, threading

EXPECTED = 'Basic ' + base64.b64encode(b'{PROXY_USER}:{PROXY_PASS}').decode()

def log(msg):
    print(msg, flush=True)

def read_head(conn):
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > 65536:
            return None
    return data

def pipe(a, b):
    try:
        while True:
            ready, _, _ = select.select([a, b], [], [])
            for sock in ready:
                chunk = sock.recv(65536)
                if not chunk:
                    return
                (b if sock is a else a).sendall(chunk)
    except OSError:
        return

def handle(conn):
    try:
        head = read_head(conn)
        if head is None:
            # Readiness probes connect and close without sending a request.
            return
        lines = head.decode('latin-1').split('\r\n')
        parts = lines[0].split()
        if len(parts) < 2 or parts[0].upper() != 'CONNECT':
            log('NON_CONNECT %s' % lines[0])
            conn.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n')
            return
        target = parts[1]
        auth = None
        for line in lines[1:]:
            if line.lower().startswith('proxy-authorization:'):
                auth = line.split(':', 1)[1].strip()
        if auth != EXPECTED:
            log('CONNECT %s auth=fail' % target)
            conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                         b'Proxy-Authenticate: Basic realm="corp"\r\n'
                         b'Content-Length: 0\r\n\r\n')
            return
        host, _, port = target.rpartition(':')
        host = host.strip('[]')
        try:
            upstream = socket.create_connection((host, int(port)), timeout=10)
        except OSError:
            log('CONNECT %s auth=ok dial=fail' % target)
            conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
            return
        log('CONNECT %s auth=ok' % target)
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        pipe(conn, upstream)
        upstream.close()
    except OSError:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', {PROXY_PORT}))
server.listen(64)
log('proxy-listening')
while True:
    client, _ = server.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
"#
    )
}

/// A TLS server with a self-signed certificate, serving one identifying marker.
///
/// The sandbox workload uses an unverified TLS context, so the certificate only
/// needs to exist — but the TLS handshake itself must be real, because it is
/// what proves bytes flowed end to end through the tunnel.
fn tls_upstream_script(common_name: &str, marker: &str) -> String {
    format!(
        r#"
import http.server, os, ssl, subprocess, tempfile

workdir = tempfile.mkdtemp()
key = os.path.join(workdir, 'key.pem')
crt = os.path.join(workdir, 'cert.pem')
subprocess.run(
    ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
     '-keyout', key, '-out', crt, '-days', '1', '-subj', '/CN={common_name}'],
    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{{"upstream":"{marker}"}}'
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

class Server(http.server.HTTPServer):
    # Readiness probes open a bare TCP connection and close it; the failed
    # handshake is expected and must not spam the log.
    def handle_error(self, request, client_address):
        pass

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(crt, key)
server = Server(('0.0.0.0', {UPSTREAM_PORT}), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print('tls-upstream-listening', flush=True)
server.serve_forever()
"#
    )
}

/// Workload: one approved HTTPS request, one denied, then idle so the test can
/// inspect the live sandbox's Podman secret before deleting it.
fn workload_script() -> String {
    format!(
        r"
import json, ssl, time, urllib.request

ctx = ssl._create_unverified_context()

def fetch(url, retries):
    last = {{'status': -1, 'error': 'not attempted'}}
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(url, timeout=30, context=ctx) as resp:
                return {{'status': resp.status, 'body': resp.read().decode()}}
        except Exception as err:
            last = {{'status': -1, 'error': str(err)}}
            time.sleep(1)
    return last

# The approved request is retried: policy reload during sandbox startup can
# transiently surface as a 403 in the forward proxy.
print('ALLOWED_RESULT ' + json.dumps(
    fetch('https://{ALLOWED_ALIAS}:{UPSTREAM_PORT}/', 6)), flush=True)
# The denied request must fail, so a single attempt is enough.
print('DENIED_RESULT ' + json.dumps(
    fetch('https://{DENIED_ALIAS}:{UPSTREAM_PORT}/', 1)), flush=True)
print('{READY_MARKER}', flush=True)
while True:
    time.sleep(1)
"
    )
}

/// Policy allowing only the approved upstream. `tls: skip` keeps the tunnel raw
/// so the workload's TLS session runs end to end to the upstream, which is what
/// makes the proxied CONNECT path observable.
fn policy_yaml() -> String {
    format!(
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
  corporate_proxy_e2e:
    name: corporate_proxy_e2e
    endpoints:
      - host: {ALLOWED_ALIAS}
        port: {UPSTREAM_PORT}
        tls: skip
        enforcement: enforce
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
    binaries:
      - path: /usr/bin/curl
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.venv/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    )
}

/// Appends corporate-proxy keys to the harness-generated gateway TOML and
/// restores the original file when dropped.
///
/// The `[openshell.drivers.podman]` table is the last one the harness writes,
/// so appending bare keys lands in that table without introducing a duplicate
/// table header.
struct GatewayProxyConfig {
    config_path: PathBuf,
    original: Vec<u8>,
    restored: bool,
}

impl GatewayProxyConfig {
    /// Locate the gateway's `--config` path from the wrapper's args file.
    fn config_path_from_args() -> Result<PathBuf, String> {
        let args_file = std::env::var("OPENSHELL_E2E_GATEWAY_ARGS_FILE")
            .map_err(|_| "OPENSHELL_E2E_GATEWAY_ARGS_FILE must be set".to_string())?;
        let raw = std::fs::read(&args_file)
            .map_err(|err| format!("read gateway args file '{args_file}': {err}"))?;
        let args: Vec<String> = raw
            .split(|byte| *byte == 0)
            .filter(|arg| !arg.is_empty())
            .map(|arg| String::from_utf8_lossy(arg).into_owned())
            .collect();
        args.iter()
            .position(|arg| arg == "--config")
            .and_then(|index| args.get(index + 1))
            .map(PathBuf::from)
            .ok_or_else(|| format!("no --config argument in gateway args file '{args_file}'"))
    }

    /// Rewrite the gateway config with corporate-proxy settings and restart the
    /// gateway so the Podman driver picks them up.
    async fn apply(proxy_url: &str, auth_file: &str) -> Result<Self, String> {
        let config_path = Self::config_path_from_args()?;
        let original = std::fs::read(&config_path)
            .map_err(|err| format!("read gateway config '{}': {err}", config_path.display()))?;

        let mut updated = original.clone();
        if !updated.ends_with(b"\n") {
            updated.push(b'\n');
        }
        updated.extend_from_slice(
            format!(
                "https_proxy = \"{proxy_url}\"\n\
                 proxy_auth_file = \"{auth_file}\"\n\
                 proxy_auth_allow_insecure = true\n"
            )
            .as_bytes(),
        );
        std::fs::write(&config_path, &updated)
            .map_err(|err| format!("write gateway config '{}': {err}", config_path.display()))?;

        let guard = Self {
            config_path,
            original,
            restored: false,
        };
        restart_gateway().await?;
        Ok(guard)
    }

    /// Restore the original config and restart the gateway.
    async fn restore(&mut self) -> Result<(), String> {
        if self.restored {
            return Ok(());
        }
        std::fs::write(&self.config_path, &self.original).map_err(|err| {
            format!(
                "restore gateway config '{}': {err}",
                self.config_path.display()
            )
        })?;
        restart_gateway().await?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for GatewayProxyConfig {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        // Panic path: put the original config back and synchronously restart the
        // gateway so later test binaries in this run inherit neither the proxy
        // settings on disk nor the temporary configuration still loaded in the
        // running process. Nothing else restarts it here: the only
        // `ManagedGateway` is the short-lived one inside `restart_gateway`, and
        // its `Drop` only calls `start`, which does not reload config for an
        // already-running gateway.
        let _ = std::fs::write(&self.config_path, &self.original);
        if let Ok(Some(gateway)) = ManagedGateway::from_env() {
            let _ = gateway.stop();
            let _ = gateway.start();
        }
    }
}

async fn restart_gateway() -> Result<(), String> {
    let gateway = ManagedGateway::from_env()?
        .ok_or_else(|| "managed gateway metadata disappeared".to_string())?;
    gateway.stop()?;
    gateway.start()?;
    wait_for_healthy(Duration::from_secs(120)).await
}

/// Names of the per-sandbox corporate proxy credential secrets.
fn proxy_auth_secret_names() -> Result<Vec<String>, String> {
    let engine = ContainerEngine::from_env()?;
    let output = engine
        .command()
        .args(["secret", "ls", "--format", "{{.Name}}"])
        .output()
        .map_err(|err| format!("list container secrets: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "secret ls failed (exit {:?}):\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|name| name.starts_with(SECRET_PREFIX))
        .map(ToOwned::to_owned)
        .collect())
}

async fn wait_for_secret_removal(secret: &str, timeout: Duration) -> Result<(), String> {
    let start = std::time::Instant::now();
    loop {
        if !proxy_auth_secret_names()?.iter().any(|name| name == secret) {
            return Ok(());
        }
        if start.elapsed() > timeout {
            return Err(format!(
                "proxy-auth secret '{secret}' still present {}s after sandbox deletion",
                timeout.as_secs()
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Assert the workload's results and the proxy's own record of what it saw.
///
/// `output` is the sandbox's stdout; `proxy_logs` is the fake proxy's log,
/// which is the only place the CONNECT target form and the credential outcome
/// are observable.
fn assert_proxied_egress(output: &str, proxy_logs: &str, allowed_ip: &str, denied_ip: &str) {
    // The approved request succeeded and its body came from the upstream,
    // proving bytes traversed the tunnel rather than the proxy short-circuiting.
    assert!(
        output.contains("ALLOWED_RESULT") && output.contains(ALLOWED_MARKER),
        "approved HTTPS request should have reached the upstream through the proxy:\n{output}"
    );
    assert!(
        output.contains(r#""status": 200"#),
        "approved HTTPS request should have returned 200:\n{output}"
    );

    // The denied destination failed inside the sandbox — and specifically with
    // a 403 from the supervisor's own proxy. Asserting the status rather than
    // just "it failed" is what rules out a vacuous pass: an unresolvable host
    // or a dead upstream would also fail, but neither would prove the request
    // was stopped by policy.
    let denied_line = output
        .lines()
        .find(|line| line.contains("DENIED_RESULT"))
        .unwrap_or_default();
    assert!(
        denied_line.contains(r#""status": -1"#) && denied_line.contains("403"),
        "denied destination should have been refused by policy with 403:\n{output}"
    );
    assert!(
        !output.contains(DENIED_MARKER),
        "denied destination's body must never reach the sandbox:\n{output}"
    );

    // Credentials arrived through the mounted secret: the proxy answers 407
    // without them, so a completed CONNECT is proof of delivery.
    assert!(
        proxy_logs.contains(&format!("CONNECT {allowed_ip}:{UPSTREAM_PORT} auth=ok")),
        "proxy should have seen an authenticated validated-IP CONNECT to \
         {allowed_ip}:{UPSTREAM_PORT}.\nProxy logs:\n{proxy_logs}\nSandbox output:\n{output}"
    );
    assert!(
        !proxy_logs.contains("auth=fail"),
        "proxy must never see an unauthenticated CONNECT:\n{proxy_logs}"
    );

    // The CONNECT target is a validated IP, not a hostname — the proxy performs
    // no DNS resolution of its own, so the tunnel stays bound to the address
    // that passed SSRF and allowed_ips validation.
    assert!(
        !proxy_logs.contains(ALLOWED_ALIAS),
        "CONNECT should target a validated IP, not the hostname:\n{proxy_logs}"
    );

    // The denied destination never reached the proxy: policy denial happens
    // before any upstream contact. The port is part of the needle so a shorter
    // IP cannot match inside a longer one (10.89.0.2 within 10.89.0.20).
    assert!(
        !proxy_logs.contains(&format!("{denied_ip}:{UPSTREAM_PORT}"))
            && !proxy_logs.contains(DENIED_ALIAS),
        "policy-denied destination {denied_ip} ({DENIED_ALIAS}) must never reach the proxy:\n{proxy_logs}"
    );
}

#[tokio::test]
async fn podman_corporate_proxy_routes_approved_tls_egress() {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("podman") {
        eprintln!("Skipping corporate proxy test: e2e driver is not podman");
        return;
    }
    if ManagedGateway::from_env()
        .expect("load managed e2e gateway metadata")
        .is_none()
    {
        eprintln!("Skipping corporate proxy test: e2e gateway is not managed by this test run");
        return;
    }

    // ── Fixtures on the shared e2e network ────────────────────────────
    let proxy = SupportContainer::start_python(PROXY_ALIAS, &proxy_script(), PROXY_PORT)
        .await
        .expect("start fake corporate proxy");
    let allowed = SupportContainer::start_python(
        ALLOWED_ALIAS,
        &tls_upstream_script(ALLOWED_ALIAS, ALLOWED_MARKER),
        UPSTREAM_PORT,
    )
    .await
    .expect("start approved TLS upstream");
    // A separate container, not another alias on the approved one: CONNECT
    // targets are IPs, so a shared IP would make "the proxy never saw the
    // denied destination" unprovable.
    let denied = SupportContainer::start_python(
        DENIED_ALIAS,
        &tls_upstream_script(DENIED_ALIAS, DENIED_MARKER),
        UPSTREAM_PORT,
    )
    .await
    .expect("start denied TLS upstream");

    let allowed_ip = allowed.ip().expect("resolve approved upstream IP");
    let denied_ip = denied.ip().expect("resolve denied upstream IP");
    assert_ne!(
        allowed_ip, denied_ip,
        "approved and denied upstreams must have distinct IPs"
    );

    // ── Point the gateway at the corporate proxy ──────────────────────
    let mut auth_file = NamedTempFile::new().expect("create proxy auth file");
    writeln!(auth_file, "{PROXY_USER}:{PROXY_PASS}").expect("write proxy credentials");
    auth_file.flush().expect("flush proxy credentials");
    let auth_path = auth_file
        .path()
        .to_str()
        .expect("proxy auth path should be utf-8")
        .to_string();

    let secrets_before = proxy_auth_secret_names().expect("snapshot proxy-auth secrets");

    let mut gateway_config =
        GatewayProxyConfig::apply(&format!("http://{PROXY_ALIAS}:{PROXY_PORT}"), &auth_path)
            .await
            .expect("apply corporate proxy gateway config");

    // ── Run the workload ──────────────────────────────────────────────
    let mut policy = NamedTempFile::new().expect("create policy file");
    policy
        .write_all(policy_yaml().as_bytes())
        .expect("write policy file");
    policy.flush().expect("flush policy file");
    let policy_path = policy
        .path()
        .to_str()
        .expect("policy path should be utf-8")
        .to_string();

    let script = workload_script();
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--policy", &policy_path],
        &["python3", "-c", &script],
        READY_MARKER,
    )
    .await
    .expect("create sandbox behind the corporate proxy");

    assert_proxied_egress(
        &sandbox.create_output,
        &proxy.logs().expect("read fake proxy logs"),
        &allowed_ip,
        &denied_ip,
    );

    // ── Secret lifecycle ──────────────────────────────────────────────
    let secrets_live = proxy_auth_secret_names().expect("list proxy-auth secrets while sandbox up");
    let new_secrets: Vec<&String> = secrets_live
        .iter()
        .filter(|name| !secrets_before.contains(name))
        .collect();
    assert_eq!(
        new_secrets.len(),
        1,
        "exactly one proxy-auth secret should exist for the running sandbox. \
         Before: {secrets_before:?}, now: {secrets_live:?}"
    );
    let sandbox_secret = new_secrets[0].clone();

    sandbox.cleanup().await;

    wait_for_secret_removal(&sandbox_secret, Duration::from_secs(60))
        .await
        .expect("sandbox deletion should remove the proxy-auth secret");

    gateway_config
        .restore()
        .await
        .expect("restore gateway config");
}
