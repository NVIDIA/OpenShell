// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-vm")]

//! Cross-layer E2E coverage for corporate forward-proxy egress from microVM
//! sandboxes (issue #3088).
//!
//! The VM counterpart of `podman_corporate_proxy.rs`. It drives the whole
//! chain end to end:
//!
//! gateway TOML → VM driver config → driver subprocess argv → per-sandbox
//! overlay staging (credential, CA, supervisor argument list) → guest init
//! script → supervisor CLI parsing → policy evaluation → proxied CONNECT
//!
//! and asserts the properties only a real run can establish:
//!
//! 1. A policy-approved HTTPS request reaches its destination *through* the
//!    proxy, with a validated IP as the CONNECT target.
//! 2. A policy-denied destination never reaches the proxy at all.
//! 3. Credentials arrive through the overlay-staged file — the proxy answers
//!    407 to an unauthenticated CONNECT, so a 200 proves delivery.
//! 4. A port-qualified `no_proxy` entry bypasses the proxy for that port only.
//! 5. An `https://` proxy works when its CA is supplied via `proxy_ca_bundle`.
//! 6. An incoherent setting is fatal at gateway startup rather than
//!    degrading to a direct dial.
//!
//! Fixtures run as host processes and are reached from the guest through
//! gvproxy's `host.openshell.internal` alias, which is also what proves the
//! documented host-loopback reachability rule for the libkrun backend. That
//! rule is libkrun-specific: QEMU/TAP sandboxes (GPU) cannot reach a
//! gateway-host proxy at all, and the driver rejects such a configuration at
//! launch — see `qemu_backend_rejects_a_gateway_host_proxy` in the driver.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use openshell_e2e::harness::cli::wait_for_healthy;
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::host_process::HostPythonFixture;
use openshell_e2e::harness::port::find_free_port;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serial_test::serial;
use tempfile::NamedTempFile;

/// The gvproxy host alias seeded into every guest's `/etc/hosts`. A host-bound
/// fixture is reachable from the guest only through this name.
const HOST_ALIAS: &str = "host.openshell.internal";
/// The address `HOST_ALIAS` resolves to inside the guest, and therefore the
/// CONNECT target the supervisor validates and sends to the proxy.
const GVPROXY_HOST_LOOPBACK_IP: &str = "192.168.127.254";

const PROXY_USER: &str = "proxyuser";
const PROXY_PASS: &str = "proxypass";

const ALLOWED_MARKER: &str = "vm-corp-proxy-e2e-allowed-upstream";
const DENIED_MARKER: &str = "vm-corp-proxy-e2e-denied-upstream";
const BYPASS_MARKER: &str = "vm-corp-proxy-e2e-bypass-upstream";
const READY_MARKER: &str = "vm-corp-proxy-e2e-workload-done";

/// Ports the fixtures bind and the guest addresses them by.
struct FixturePorts {
    proxy: u16,
    allowed: u16,
    denied: u16,
    bypass: u16,
}

impl FixturePorts {
    fn pick() -> Self {
        Self {
            proxy: find_free_port(),
            allowed: find_free_port(),
            denied: find_free_port(),
            bypass: find_free_port(),
        }
    }
}

/// Python that maps the guest-side host address back to the host loopback.
///
/// The supervisor sends the *validated* CONNECT target, which inside the guest
/// is gvproxy's host-loopback address. That address means nothing on the host
/// where the proxy fixture runs, so the fixture rewrites it to `127.0.0.1`
/// when dialing — standing in for the corporate network's own routing to the
/// destination. The target the fixture *logs* is left untouched, so the
/// validated-IP assertion still tests the supervisor's behaviour rather than
/// the fixture's.
const HOST_REWRITE: &str = "
def dial_host(host):
    return '127.0.0.1' if host == '192.168.127.254' else host
";

/// A forward proxy that requires Basic auth and logs every CONNECT it sees.
///
/// The log lines are the test's evidence: they record the exact CONNECT target
/// (proving validated-IP form, and which destination ports were proxied at
/// all) and whether credentials arrived.
fn proxy_script(port: u16) -> String {
    format!(
        r#"
import base64, select, socket, threading
{HOST_REWRITE}
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
            upstream = socket.create_connection((dial_host(host), int(port)), timeout=10)
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
server.bind(('0.0.0.0', {port}))
server.listen(64)
log('proxy-listening')
while True:
    client, _ = server.accept()
    threading.Thread(target=handle, args=(client,), daemon=True).start()
"#
    )
}

// Delimits the proxy's CA certificate in its output, so the test can recover it
// and hand it back as the corporate CA bundle.
const CA_BEGIN: &str = "---PROXY-CA-BEGIN---";
const CA_END: &str = "---PROXY-CA-END---";

/// A forward proxy that terminates TLS with a CA-signed certificate and logs
/// every CONNECT it sees.
///
/// It mints a corporate CA and a listener leaf signed by it (SAN = the host
/// alias, which is the name the supervisor uses for SNI), serves the leaf, and
/// prints the CA between [`CA_BEGIN`]/[`CA_END`] so the test can trust it via
/// `proxy_ca_bundle`. The listener certificate must be a leaf: rustls rejects a
/// `CA:TRUE` certificate presented as an end-entity certificate. No Basic auth
/// here — this test isolates the `https://` proxy plus corporate-CA path.
/// Mint a corporate CA plus a listener leaf signed by it, and print the CA.
///
/// Split out of [`tls_proxy_script`] to keep that function within clippy's
/// line budget. The listener certificate must be a leaf: rustls rejects a
/// `CA:TRUE` certificate presented as an end-entity certificate, so a single
/// self-signed `openssl req -x509` certificate cannot serve as both the
/// anchor and the listener identity. Signing a leaf also matches what a real
/// intercepting proxy does.
fn tls_proxy_pki_preamble() -> String {
    format!(
        r"
workdir = tempfile.mkdtemp()
ca_key = os.path.join(workdir, 'ca-key.pem')
ca_crt = os.path.join(workdir, 'ca.pem')
leaf_key = os.path.join(workdir, 'leaf-key.pem')
leaf_csr = os.path.join(workdir, 'leaf.csr')
leaf_crt = os.path.join(workdir, 'leaf.pem')
chain = os.path.join(workdir, 'chain.pem')
ext = os.path.join(workdir, 'leaf.ext')

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', ca_key, '-out', ca_crt, '-days', '1',
    '-subj', '/CN=vm-corp-proxy-e2e-ca')

with open(ext, 'w') as fh:
    fh.write('basicConstraints=critical,CA:FALSE\n'
             'subjectAltName=DNS:{HOST_ALIAS}\n'
             'extendedKeyUsage=serverAuth\n')
run('openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', leaf_key, '-out', leaf_csr, '-subj', '/CN={HOST_ALIAS}')
run('openssl', 'x509', '-req', '-in', leaf_csr, '-CA', ca_crt, '-CAkey', ca_key,
    '-CAcreateserial', '-out', leaf_crt, '-days', '1', '-extfile', ext)

with open(chain, 'w') as out:
    for part in (leaf_crt, ca_crt):
        with open(part) as fh:
            out.write(fh.read())

with open(ca_crt) as fh:
    print('{CA_BEGIN}\n' + fh.read() + '{CA_END}', flush=True)
"
    )
}

fn tls_proxy_script(port: u16) -> String {
    let pki = tls_proxy_pki_preamble();
    format!(
        r"
import os, select, socket, ssl, subprocess, tempfile, threading
{HOST_REWRITE}
{pki}

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
            return
        lines = head.decode('latin-1').split('\r\n')
        parts = lines[0].split()
        if len(parts) < 2 or parts[0].upper() != 'CONNECT':
            log('NON_CONNECT %s' % lines[0])
            conn.sendall(b'HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n')
            return
        target = parts[1]
        host, _, port = target.rpartition(':')
        host = host.strip('[]')
        try:
            upstream = socket.create_connection((dial_host(host), int(port)), timeout=10)
        except OSError:
            log('CONNECT %s dial=fail' % target)
            conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n')
            return
        log('CONNECT %s ok' % target)
        conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        pipe(conn, upstream)
        upstream.close()
    except OSError:
        pass
    finally:
        conn.close()

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(chain, leaf_key)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', {port}))
server.listen(64)
log('tls-proxy-listening')
while True:
    raw, _ = server.accept()
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except OSError:
        # Readiness probes open a bare TCP connection; the failed handshake is
        # expected and must not spam the log.
        raw.close()
        continue
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
"
    )
}

/// Extract the proxy's CA certificate PEM from its output.
fn ca_cert_from_logs(logs: &str) -> Result<String, String> {
    let start = logs
        .find(CA_BEGIN)
        .ok_or_else(|| format!("proxy CA begin marker not found in logs:\n{logs}"))?
        + CA_BEGIN.len();
    let end = logs[start..]
        .find(CA_END)
        .ok_or_else(|| format!("proxy CA end marker not found in logs:\n{logs}"))?;
    Ok(logs[start..start + end].trim().to_string())
}

/// A TLS server with a self-signed certificate, serving one identifying marker.
///
/// The workload uses an unverified TLS context, so the certificate only needs
/// to exist — but the handshake itself must be real, because it is what proves
/// bytes flowed end to end through the tunnel.
fn tls_upstream_script(marker: &str, port: u16) -> String {
    format!(
        r#"
import http.server, os, ssl, subprocess, tempfile

workdir = tempfile.mkdtemp()
key = os.path.join(workdir, 'key.pem')
crt = os.path.join(workdir, 'cert.pem')
subprocess.run(
    ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
     '-keyout', key, '-out', crt, '-days', '1', '-subj', '/CN={HOST_ALIAS}'],
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
server = Server(('0.0.0.0', {port}), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print('tls-upstream-listening', flush=True)
server.serve_forever()
"#
    )
}

/// Workload: one approved HTTPS request through the proxy, one policy-denied,
/// and one that `no_proxy` should send direct.
///
/// Run through `ExecSandbox` rather than as the sandbox's main process. The VM
/// driver base64-encodes the main-process spec into the guest environment,
/// which libkrun passes on the kernel command line, so a script this size as
/// the main process aborts the VM with a `TooLarge` cmdline error before boot.
fn workload_script(ports: &FixturePorts) -> String {
    let (allowed, denied, bypass) = (ports.allowed, ports.denied, ports.bypass);
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

# The approved requests are retried: policy reload during sandbox startup can
# transiently surface as a 403 in the forward proxy.
print('ALLOWED_RESULT ' + json.dumps(
    fetch('https://{HOST_ALIAS}:{allowed}/', 6)), flush=True)
print('BYPASS_RESULT ' + json.dumps(
    fetch('https://{HOST_ALIAS}:{bypass}/', 6)), flush=True)
# The denied request must fail, so a single attempt is enough.
print('DENIED_RESULT ' + json.dumps(
    fetch('https://{HOST_ALIAS}:{denied}/', 1)), flush=True)
print('{READY_MARKER}', flush=True)
"
    )
}

/// Policy allowing the proxied and the bypassed upstream, but not the denied
/// one. `tls: skip` keeps the tunnel raw so the workload's TLS session runs end
/// to end, which is what makes the proxied CONNECT path observable.
fn policy_yaml(ports: &FixturePorts) -> String {
    let (allowed, bypass) = (ports.allowed, ports.bypass);
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
  vm_corporate_proxy_e2e:
    name: vm_corporate_proxy_e2e
    endpoints:
      - host: {HOST_ALIAS}
        port: {allowed}
        tls: skip
        enforcement: enforce
        allowed_ips:
          - "10.0.0.0/8"
          - "172.0.0.0/8"
          - "192.168.0.0/16"
          - "fc00::/7"
      - host: {HOST_ALIAS}
        port: {bypass}
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
/// `[openshell.drivers.vm]` is the last table `e2e-vm.sh` writes, so appending
/// bare keys lands in that table without introducing a duplicate header.
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

    /// Append raw TOML lines to `[openshell.drivers.vm]` and restart the
    /// gateway, without waiting for it to become healthy.
    ///
    /// Used directly by the fail-closed case, which expects the gateway *not*
    /// to come up.
    fn apply_raw(extra: &str) -> Result<Self, String> {
        let config_path = Self::config_path_from_args()?;
        let original = std::fs::read(&config_path)
            .map_err(|err| format!("read gateway config '{}': {err}", config_path.display()))?;

        let mut updated = original.clone();
        if !updated.ends_with(b"\n") {
            updated.push(b'\n');
        }
        updated.extend_from_slice(extra.as_bytes());
        std::fs::write(&config_path, &updated)
            .map_err(|err| format!("write gateway config '{}': {err}", config_path.display()))?;

        let guard = Self {
            config_path,
            original,
            restored: false,
        };
        let gateway = ManagedGateway::from_env()?
            .ok_or_else(|| "managed gateway metadata disappeared".to_string())?;
        gateway.stop()?;
        gateway.start()?;
        Ok(guard)
    }

    /// Point the VM driver at a corporate proxy and wait for the gateway to
    /// come back healthy.
    async fn apply(
        proxy_url: &str,
        auth_file: Option<&str>,
        ca_bundle: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<Self, String> {
        let mut extra = format!("https_proxy = \"{proxy_url}\"\n");
        if let Some(auth_file) = auth_file {
            let _ = write!(
                extra,
                "proxy_auth_file = \"{auth_file}\"\nproxy_auth_allow_insecure = true\n"
            );
        }
        if let Some(ca_bundle) = ca_bundle {
            let _ = writeln!(extra, "proxy_ca_bundle = \"{ca_bundle}\"");
        }
        if let Some(no_proxy) = no_proxy {
            let _ = writeln!(extra, "no_proxy = \"{no_proxy}\"");
        }
        let guard = Self::apply_raw(&extra)?;
        wait_for_healthy(Duration::from_secs(120)).await?;
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
        let gateway = ManagedGateway::from_env()?
            .ok_or_else(|| "managed gateway metadata disappeared".to_string())?;
        gateway.stop()?;
        gateway.start()?;
        wait_for_healthy(Duration::from_secs(120)).await?;
        self.restored = true;
        Ok(())
    }
}

impl Drop for GatewayProxyConfig {
    fn drop(&mut self) {
        if self.restored {
            return;
        }
        // Panic path: put the original config back and synchronously restart
        // the gateway so later test binaries in this run inherit neither the
        // proxy settings on disk nor the configuration still loaded in the
        // running process.
        let _ = std::fs::write(&self.config_path, &self.original);
        if let Ok(Some(gateway)) = ManagedGateway::from_env() {
            let _ = gateway.stop();
            let _ = gateway.start();
        }
    }
}

/// Skip unless this run owns a VM gateway it can reconfigure.
///
/// The external-driver lane launches `openshell-driver-vm` from the shell
/// wrapper rather than from the gateway, so gateway config changes never reach
/// the driver and the test would assert against a driver that has no proxy
/// settings at all.
fn should_run(label: &str) -> bool {
    if std::env::var("OPENSHELL_E2E_DRIVER").as_deref() != Ok("vm") {
        eprintln!("Skipping {label}: e2e driver is not vm");
        return false;
    }
    if std::env::var("OPENSHELL_E2E_EXTERNAL_COMPUTE_DRIVER").as_deref() == Ok("1") {
        eprintln!("Skipping {label}: the external VM driver is not configured by the gateway");
        return false;
    }
    match ManagedGateway::from_env() {
        Ok(Some(_)) => true,
        Ok(None) => {
            eprintln!("Skipping {label}: e2e gateway is not managed by this test run");
            false
        }
        Err(err) => panic!("load managed e2e gateway metadata: {err}"),
    }
}

/// Write a temp file and return its path as an owned `String`.
fn temp_file_with(contents: &str, label: &str) -> (NamedTempFile, String) {
    let mut file = NamedTempFile::new().unwrap_or_else(|err| panic!("create {label}: {err}"));
    file.write_all(contents.as_bytes())
        .unwrap_or_else(|err| panic!("write {label}: {err}"));
    file.flush()
        .unwrap_or_else(|err| panic!("flush {label}: {err}"));
    let path = file
        .path()
        .to_str()
        .unwrap_or_else(|| panic!("{label} path should be utf-8"))
        .to_string();
    (file, path)
}

/// Assert the workload's results and the proxy's own record of what it saw.
fn assert_proxied_egress(output: &str, proxy_logs: &str, ports: &FixturePorts) {
    assert!(
        output.contains(READY_MARKER),
        "workload did not finish; output:\n{output}"
    );

    // The approved request succeeded and its body came from the upstream,
    // proving bytes traversed the tunnel rather than the proxy short-circuiting.
    assert!(
        output.contains("ALLOWED_RESULT") && output.contains(ALLOWED_MARKER),
        "approved HTTPS request should have reached the upstream through the proxy:\n{output}"
    );

    // The CONNECT target is the validated resolved address, not the hostname,
    // and it arrived authenticated -- which is only possible if the credential
    // staged into the overlay reached the supervisor.
    assert!(
        proxy_logs.contains(&format!(
            "CONNECT {GVPROXY_HOST_LOOPBACK_IP}:{} auth=ok",
            ports.allowed
        )),
        "proxy should have seen an authenticated validated-IP CONNECT to the approved upstream:\n{proxy_logs}"
    );
    assert!(
        !proxy_logs.contains("auth=fail"),
        "the proxy credential should have been sent on the first CONNECT:\n{proxy_logs}"
    );

    // The denied destination failed inside the sandbox, and never reached the
    // proxy: policy stops it before the upstream dial.
    assert!(
        !proxy_logs.contains(&format!(":{}", ports.denied)),
        "policy-denied destination must never reach the proxy:\n{proxy_logs}"
    );
    assert!(
        !output.contains(DENIED_MARKER),
        "policy-denied upstream body must never reach the workload:\n{output}"
    );

    // The no_proxy entry is port-qualified, so this destination was dialed
    // directly while the approved one above still went through the proxy.
    assert!(
        output.contains("BYPASS_RESULT") && output.contains(BYPASS_MARKER),
        "no_proxy destination should have been reached by a direct dial:\n{output}"
    );
    assert!(
        !proxy_logs.contains(&format!(":{}", ports.bypass)),
        "no_proxy destination must never reach the proxy:\n{proxy_logs}"
    );
}

#[tokio::test]
#[serial(vm_corporate_proxy)]
async fn vm_corporate_proxy_routes_approved_tls_egress() {
    if !should_run("corporate proxy test") {
        return;
    }

    let ports = FixturePorts::pick();

    // ── Host fixtures, reached from the guest through the gvproxy alias ──
    let proxy = HostPythonFixture::start(&proxy_script(ports.proxy), ports.proxy)
        .await
        .expect("start fake corporate proxy");
    let _allowed = HostPythonFixture::start(
        &tls_upstream_script(ALLOWED_MARKER, ports.allowed),
        ports.allowed,
    )
    .await
    .expect("start approved TLS upstream");
    let _denied = HostPythonFixture::start(
        &tls_upstream_script(DENIED_MARKER, ports.denied),
        ports.denied,
    )
    .await
    .expect("start denied TLS upstream");
    let _bypass = HostPythonFixture::start(
        &tls_upstream_script(BYPASS_MARKER, ports.bypass),
        ports.bypass,
    )
    .await
    .expect("start no_proxy TLS upstream");

    // ── Point the VM driver at the corporate proxy ────────────────────
    let (_auth_file, auth_path) =
        temp_file_with(&format!("{PROXY_USER}:{PROXY_PASS}\n"), "proxy auth file");

    let mut gateway_config = GatewayProxyConfig::apply(
        &format!("http://{HOST_ALIAS}:{}", ports.proxy),
        Some(&auth_path),
        None,
        // Port-qualified, so only this destination port bypasses the proxy.
        Some(&format!("{HOST_ALIAS}:{}", ports.bypass)),
    )
    .await
    .expect("apply corporate proxy gateway config");

    // ── Run the workload ──────────────────────────────────────────────
    let (_policy, policy_path) = temp_file_with(&policy_yaml(&ports), "policy file");
    let script = workload_script(&ports);
    let mut sandbox =
        SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
            .await
            .expect("create VM sandbox behind the corporate proxy");

    assert_proxied_egress(
        &sandbox.create_output,
        &proxy.logs().expect("read fake proxy logs"),
        &ports,
    );

    sandbox.cleanup().await;

    gateway_config
        .restore()
        .await
        .expect("restore gateway config");
}

#[tokio::test]
#[serial(vm_corporate_proxy)]
async fn vm_corporate_proxy_trusts_ca_bundle_for_https_proxy() {
    if !should_run("https corporate proxy test") {
        return;
    }

    let ports = FixturePorts::pick();

    let proxy = HostPythonFixture::start(&tls_proxy_script(ports.proxy), ports.proxy)
        .await
        .expect("start fake https corporate proxy");
    let _allowed = HostPythonFixture::start(
        &tls_upstream_script(ALLOWED_MARKER, ports.allowed),
        ports.allowed,
    )
    .await
    .expect("start approved TLS upstream");
    let _denied = HostPythonFixture::start(
        &tls_upstream_script(DENIED_MARKER, ports.denied),
        ports.denied,
    )
    .await
    .expect("start denied TLS upstream");
    let _bypass = HostPythonFixture::start(
        &tls_upstream_script(BYPASS_MARKER, ports.bypass),
        ports.bypass,
    )
    .await
    .expect("start second approved TLS upstream");

    // The proxy prints its CA on startup; the supervisor must trust it to
    // complete the TLS handshake with the proxy at all.
    let ca_pem = ca_cert_from_logs(&proxy.logs().expect("read https proxy logs"))
        .expect("recover corporate CA from proxy output");
    let (_ca_file, ca_path) = temp_file_with(&ca_pem, "corporate CA bundle");

    let mut gateway_config = GatewayProxyConfig::apply(
        &format!("https://{HOST_ALIAS}:{}", ports.proxy),
        None,
        Some(&ca_path),
        None,
    )
    .await
    .expect("apply https corporate proxy gateway config");

    let (_policy, policy_path) = temp_file_with(&policy_yaml(&ports), "policy file");
    let script = workload_script(&ports);
    let mut sandbox =
        SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
            .await
            .expect("create VM sandbox behind the https corporate proxy");

    let proxy_logs = proxy.logs().expect("read https proxy logs");
    assert!(
        sandbox.create_output.contains(ALLOWED_MARKER),
        "approved upstream body missing -- egress did not complete through the https proxy:\n{}",
        sandbox.create_output
    );
    assert!(
        proxy_logs.contains(&format!(
            "CONNECT {GVPROXY_HOST_LOOPBACK_IP}:{} ok",
            ports.allowed
        )),
        "https proxy should have seen a validated-IP CONNECT to the approved upstream:\n{proxy_logs}"
    );
    assert!(
        !proxy_logs.contains(&format!(":{}", ports.denied)),
        "policy-denied destination must never reach the https proxy:\n{proxy_logs}"
    );

    sandbox.cleanup().await;

    gateway_config
        .restore()
        .await
        .expect("restore gateway config");
}

#[tokio::test]
#[serial(vm_corporate_proxy)]
async fn vm_corporate_proxy_rejects_incoherent_configuration() {
    if !should_run("corporate proxy fail-closed test") {
        return;
    }

    // A bypass list without a proxy URL means the operator believed proxying
    // was in effect. Accepting it would leave every dial direct while looking
    // configured, so the gateway must refuse to start instead.
    let mut gateway_config = GatewayProxyConfig::apply_raw("no_proxy = \"10.0.0.0/8\"\n")
        .expect("apply incoherent corporate proxy gateway config");

    let health = wait_for_healthy(Duration::from_secs(20)).await;
    assert!(
        health.is_err(),
        "gateway must not serve traffic with an incoherent [openshell.drivers.vm] proxy table"
    );

    let log_path = std::env::var("OPENSHELL_E2E_GATEWAY_LOG").expect("gateway log path");
    let log = std::fs::read_to_string(&log_path).expect("read gateway log");
    // The message must name the offending key rather than surfacing as an
    // opaque driver-readiness timeout. Matched loosely on the key names so
    // this does not break on error-wrapping changes.
    assert!(
        log.contains("no_proxy") && log.contains("https_proxy"),
        "the startup error must name the offending key; gateway log tail:\n{}",
        log.lines().rev().take(40).collect::<Vec<_>>().join("\n")
    );

    gateway_config
        .restore()
        .await
        .expect("restore gateway config");
}
