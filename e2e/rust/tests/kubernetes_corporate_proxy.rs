// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Kubernetes wiring coverage for authenticated corporate forward proxies.
//!
//! The shell wrapper configures the gateway before it starts, creates the
//! credential Secret, and forces sidecar topology. This test starts a proxy
//! and an HTTPS upstream on the host visible to sandbox pods, then proves that
//! a permitted request uses authenticated CONNECT while a policy-denied port
//! never reaches the proxy.

use std::io::Write as _;

use openshell_e2e::harness::container::HostSupportContainer;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

const HOST_ALIAS: &str = "host.openshell.internal";
const FIXTURE_PORT: u16 = 8000;
const USER: &str = "proxyuser";
const PASS: &str = "proxypass";
const MARKER: &str = "kubernetes-corporate-proxy-upstream";

fn proxy_script() -> String {
    format!(
        r#"
import base64, select, socket, threading
expected = 'Basic ' + base64.b64encode(b'{USER}:{PASS}').decode()
def head(c):
  data=b''
  while b'\r\n\r\n' not in data:
    piece=c.recv(4096)
    if not piece: return None
    data += piece
  return data
def pipe(a,b):
  try:
    while True:
      ready,_,_=select.select([a,b],[],[])
      for src in ready:
        data=src.recv(65536)
        if not data: return
        (b if src is a else a).sendall(data)
  except OSError: pass
def handle(c):
  try:
    raw=head(c)
    if raw is None: return
    lines=raw.decode('latin-1').split('\r\n')
    parts=lines[0].split()
    target=parts[1] if len(parts)>1 else 'invalid'
    auth=next((line.split(':',1)[1].strip() for line in lines[1:] if line.lower().startswith('proxy-authorization:')), '')
    if len(parts)<2 or parts[0] != 'CONNECT' or auth != expected:
      print('CONNECT %s auth=fail' % target, flush=True)
      c.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n'); return
    host,_,port=target.rpartition(':')
    try: upstream=socket.create_connection((host.strip('[]'),int(port)),timeout=10)
    except OSError:
      print('CONNECT %s auth=ok dial=fail' % target, flush=True)
      c.sendall(b'HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n'); return
    print('CONNECT %s auth=ok' % target, flush=True)
    c.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    pipe(c,upstream); upstream.close()
  except OSError: pass
  finally: c.close()
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('0.0.0.0',{FIXTURE_PORT})); s.listen(32)
print('proxy-listening',flush=True)
while True:
  c,_=s.accept(); threading.Thread(target=handle,args=(c,),daemon=True).start()
"#
    )
}

fn tls_upstream_script() -> String {
    format!(
        r#"
import http.server, os, ssl, subprocess, tempfile
d=tempfile.mkdtemp(); key=os.path.join(d,'key'); cert=os.path.join(d,'cert')
subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN={HOST_ALIAS}'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
class H(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    body=b'{MARKER}'; self.send_response(200); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
  def log_message(self,*args): pass
s=http.server.HTTPServer(('0.0.0.0',{FIXTURE_PORT}),H); ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cert,key); s.socket=ctx.wrap_socket(s.socket,server_side=True)
print('upstream-listening',flush=True); s.serve_forever()
"#
    )
}

fn policy_yaml(upstream_port: u16) -> String {
    format!(
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
  proxy_e2e:
    name: proxy_e2e
    endpoints:
      - host: {HOST_ALIAS}
        port: {upstream_port}
        tls: skip
        enforcement: enforce
        allowed_ips: ["10.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
    binaries:
      - path: "/**"
"#
    )
}

#[tokio::test]
async fn kubernetes_corporate_proxy_uses_secret_and_never_falls_back() {
    if std::env::var("OPENSHELL_E2E_KUBE_CORPORATE_PROXY").as_deref() != Ok("1") {
        eprintln!("Skipping corporate proxy test: fixture mode is disabled");
        return;
    }
    let proxy_port: u16 = std::env::var("OPENSHELL_E2E_CORPORATE_PROXY_PORT")
        .expect("proxy fixture port must be supplied by Kubernetes e2e wrapper")
        .parse()
        .expect("proxy fixture port must be a u16");
    let mode = std::env::var("OPENSHELL_E2E_CORPORATE_PROXY_MODE")
        .unwrap_or_else(|_| "authenticated".to_string());
    if matches!(mode.as_str(), "missing-secret" | "malformed") {
        let mut policy = NamedTempFile::new().expect("create policy file");
        policy
            .write_all(b"version: 1\nnetwork_policies: {}\n")
            .expect("write policy");
        let policy_path = policy
            .path()
            .to_str()
            .expect("UTF-8 policy path")
            .to_string();
        let error = match SandboxGuard::create(&["--policy", &policy_path, "--", "true"]).await {
            Ok(_) => panic!("invalid credential fixture must fail sandbox creation"),
            Err(error) => error,
        };
        assert!(
            error.contains("secret")
                || error.contains("credential")
                || error.contains("proxy")
                || error.contains("timed out"),
            "failure should identify the unavailable or malformed proxy credential: {error}"
        );
        return;
    }
    let proxy =
        HostSupportContainer::start_python_on_host_port(&proxy_script(), FIXTURE_PORT, proxy_port)
            .await
            .expect("start authenticated forward proxy");
    let upstream = if mode == "no-proxy" {
        let port: u16 = std::env::var("OPENSHELL_E2E_CORPORATE_PROXY_UPSTREAM_PORT")
            .expect("no-proxy fixture port must be supplied by Kubernetes e2e wrapper")
            .parse()
            .expect("no-proxy fixture port must be a u16");
        HostSupportContainer::start_python_on_host_port(&tls_upstream_script(), FIXTURE_PORT, port)
            .await
            .expect("start fixed-port TLS upstream")
    } else {
        HostSupportContainer::start_python(&tls_upstream_script(), FIXTURE_PORT)
            .await
            .expect("start TLS upstream")
    };

    let mut policy = NamedTempFile::new().expect("create policy file");
    policy
        .write_all(policy_yaml(upstream.port).as_bytes())
        .expect("write policy");
    policy.flush().expect("flush policy");
    let policy_path = policy
        .path()
        .to_str()
        .expect("UTF-8 policy path")
        .to_string();
    let allowed = format!("https://{HOST_ALIAS}:{}/", upstream.port);
    let denied = format!("https://{HOST_ALIAS}:9/");
    let script = format!(
        "import ssl, urllib.request\nctx=ssl._create_unverified_context()\n\n\ndef fetch(url):\n  try:\n    with urllib.request.urlopen(url,timeout=30,context=ctx) as r: return 'ok:'+r.read().decode()\n  except Exception as e: return 'err:'+str(e)\nprint('ALLOWED '+fetch({allowed:?}),flush=True)\nprint('DENIED '+fetch({denied:?}),flush=True)"
    );
    let sandbox = SandboxGuard::create(&["--policy", &policy_path, "--", "python3", "-c", &script])
        .await
        .expect("create sandbox through corporate proxy");
    let output = &sandbox.create_output;
    assert!(
        output.contains(MARKER),
        "approved HTTPS request must reach upstream through the proxy:\n{output}"
    );
    assert!(
        output.contains("DENIED err:") && output.contains("403"),
        "policy-denied request must fail closed with 403:\n{output}"
    );
    let logs = proxy.logs().expect("read proxy logs");
    if mode == "no-proxy" {
        assert!(
            !logs.contains("CONNECT"),
            "NO_PROXY request must bypass the corporate proxy:\n{logs}"
        );
    } else {
        assert!(
            logs.contains("auth=ok"),
            "Secret credentials must reach proxy:\n{logs}"
        );
        assert!(
            !logs.contains("auth=fail"),
            "proxy must not receive missing credentials:\n{logs}"
        );
    }
    assert!(
        !logs.contains(":9 ") && !logs.contains(":9\n"),
        "denied request must never reach proxy:\n{logs}"
    );
}
