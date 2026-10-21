// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor")]

//! Two sandboxes supervised by one shared supervisor process
//! (`supervisor_topology = "gateway"`).
//!
//! Each sandbox keeps its own policy and provider credential, stopping one
//! leaves the other supervised, and the shared runtime listener refuses
//! connections that name a stale or unknown sandbox instance route.

use std::fmt::Write as _;
use std::io::Write as _;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const TEST_HOST: &str = "host.openshell.internal";
const ALPHA: &str = "e2e-shared-alpha";
const BETA: &str = "e2e-shared-beta";
const TOKEN_ENV: &str = "E2E_SHARED_SUPERVISOR_TOKEN";
const TOPOLOGY_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-topology";
/// Instance route annotation; the key keeps its established `-session` name.
const INSTANCE_ROUTE_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
const SUPERVISOR_COMPONENT: &str = "app.kubernetes.io/component=supervisor";
const RUNTIME_PORT: u16 = 5500;

fn release_namespace() -> String {
    std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE").unwrap_or_else(|_| "openshell".to_string())
}

fn kubectl_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        && !context.trim().is_empty()
    {
        command.arg("--context").arg(context);
    }
    command
}

async fn kubectl(args: &[&str]) -> String {
    let output = kubectl_command()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .unwrap_or_else(|error| panic!("spawn kubectl {args:?}: {error}"));
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn cli(args: &[&str]) -> (bool, String) {
    let output = openshell_cmd()
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("spawn openshell CLI");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

/// The Sandbox resource of an `OpenShell` sandbox, in whichever namespace the
/// workspace mode placed it.
async fn sandbox_resource(name: &str) -> serde_json::Value {
    let output = kubectl(&[
        "get",
        "sandboxes.agents.x-k8s.io",
        "--all-namespaces",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
        "-o",
        "json",
    ])
    .await;
    let list: serde_json::Value = serde_json::from_str(&output).expect("parse Sandbox list");
    let [resource] = list["items"].as_array().expect("Sandbox items").as_slice() else {
        panic!("expected one Sandbox resource for {name}: {list}");
    };
    resource.clone()
}

/// The shared-supervisor sandbox instance route recorded for a sandbox's
/// current generation.
async fn instance_route(name: &str) -> String {
    let resource = sandbox_resource(name).await;
    let annotations = &resource["metadata"]["annotations"];
    assert_eq!(
        annotations[TOPOLOGY_ANNOTATION], "gateway",
        "{name} is not supervised by the shared supervisor: {annotations}"
    );
    annotations[INSTANCE_ROUTE_ANNOTATION]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has no sandbox instance route: {annotations}"))
        .to_string()
}

/// UID and restart count of the one shared supervisor Pod.
async fn shared_supervisor_pod() -> (String, i64) {
    let output = kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        SUPERVISOR_COMPONENT,
        "-o",
        "json",
    ])
    .await;
    let list: serde_json::Value = serde_json::from_str(&output).expect("parse Pod list");
    let pods = list["items"]
        .as_array()
        .expect("Pod items")
        .iter()
        .filter(|pod| pod["metadata"]["deletionTimestamp"].is_null())
        .collect::<Vec<_>>();
    let [pod] = pods.as_slice() else {
        panic!("expected exactly one shared supervisor Pod: {list}");
    };
    let restarts = pod["status"]["containerStatuses"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|status| status["restartCount"].as_i64().unwrap_or_default())
        .sum();
    (
        pod["metadata"]["uid"]
            .as_str()
            .expect("supervisor Pod UID")
            .to_string(),
        restarts,
    )
}

/// No dedicated supervisor Pod serves any sandbox.
async fn assert_no_dedicated_supervisors() {
    let output = kubectl(&[
        "get",
        "pods",
        "--all-namespaces",
        "-l",
        "openshell.ai/boundary-role=supervisor",
        "-o",
        "name",
    ])
    .await;
    assert!(
        output.trim().is_empty(),
        "dedicated supervisor Pods exist under the gateway topology:\n{output}"
    );
}

/// Credential a host-side endpoint received, as reported back to a sandbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Alpha,
    Beta,
    Placeholder,
    Other,
}

impl Seen {
    const fn marker(self) -> &'static str {
        match self {
            Self::Alpha => "SAW_ALPHA",
            Self::Beta => "SAW_BETA",
            Self::Placeholder => "SAW_PLACEHOLDER",
            Self::Other => "SAW_OTHER",
        }
    }
}

/// Host endpoint that reports which provider credential each request carried.
struct CredentialEndpoint {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    task: tokio::task::JoinHandle<()>,
}

impl CredentialEndpoint {
    async fn start(alpha: &str, beta: &str) -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind credential endpoint");
        let port = listener.local_addr().expect("endpoint address").port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (alpha, beta, record) = (alpha.to_string(), beta.to_string(), seen.clone());
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (alpha, beta, record) = (alpha.clone(), beta.clone(), record.clone());
                tokio::spawn(async move {
                    let _ = answer(stream, &alpha, &beta, &record).await;
                });
            }
        });
        Self { port, seen, task }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

impl Drop for CredentialEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn answer(
    stream: TcpStream,
    alpha: &str,
    beta: &str,
    record: &Mutex<Vec<Seen>>,
) -> std::io::Result<()> {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut authorization = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            authorization = value.trim().to_string();
        }
    }
    let seen = if authorization.contains(alpha) {
        Seen::Alpha
    } else if authorization.contains(beta) {
        Seen::Beta
    } else if authorization.contains("openshell:resolve:env:") {
        Seen::Placeholder
    } else {
        Seen::Other
    };
    record.lock().unwrap().push(seen);
    let body = seen.marker();
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    reader.get_mut().write_all(response.as_bytes()).await
}

fn temp_yaml(contents: &str) -> NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create temp file");
    file.write_all(contents.as_bytes())
        .expect("write temp file");
    file.flush().expect("flush temp file");
    file
}

/// A profile whose credential binds only to `port` on the test host. An
/// attached provider also contributes that endpoint to the sandbox's policy.
fn profile(id: &str, port: u16) -> NamedTempFile {
    temp_yaml(&format!(
        r"id: {id}
display_name: E2E Shared Supervisor
category: other
credentials:
  - name: token
    env_vars: [{TOKEN_ENV}]
    required: true
    auth_style: bearer
    header_name: authorization
endpoints:
  - host: {TEST_HOST}
    port: {port}
    protocol: rest
    access: full
binaries:
  - path: /usr/bin/python*
  - path: /usr/local/bin/python*
  - path: /sandbox/.uv/python/*/bin/python*
"
    ))
}

/// A sandbox policy allowing only `ports` on the test host.
fn policy(ports: &[u16]) -> NamedTempFile {
    let endpoints = ports.iter().fold(String::new(), |mut endpoints, port| {
        let _ = write!(
            endpoints,
            "      - host: {TEST_HOST}\n        port: {port}\n        protocol: rest\n        access: full\n"
        );
        endpoints
    });
    temp_yaml(&format!(
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
  shared_supervisor:
    name: shared_supervisor
    endpoints:
{endpoints}    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"
    ))
}

/// Call `port` on the test host, with the sandbox's provider placeholder when
/// `credential` is set, and print what the endpoint saw, or `DENIED`.
fn call_script(port: u16, credential: bool) -> String {
    let authorization = if credential {
        "Authorization: Bearer {token}\\r\\n"
    } else {
        ""
    };
    format!(
        r#"
import os
import socket

try:
    with socket.create_connection(({TEST_HOST:?}, {port}), timeout=15) as sock:
        token = os.environ.get({TOKEN_ENV:?}, "")
        sock.sendall(
            (f"GET /credential HTTP/1.1\r\nHost: {TEST_HOST}:{port}\r\n"
             f"{authorization}Connection: close\r\n\r\n").encode("ascii")
        )
        sock.settimeout(15)
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
    markers = [m for m in ("SAW_ALPHA", "SAW_BETA", "SAW_PLACEHOLDER", "SAW_OTHER") if m.encode() in response]
    print(markers[0] if markers else "DENIED")
except OSError:
    print("DENIED")
"#
    )
}

async fn call(sandbox: &SandboxGuard, port: u16) -> String {
    call_with(sandbox, port, true).await
}

async fn call_with(sandbox: &SandboxGuard, port: u16, credential: bool) -> String {
    let output = sandbox
        .exec(&["python3", "-c", &call_script(port, credential)])
        .await
        .unwrap_or_else(|error| panic!("call from {}: {error}", sandbox.name));
    output
        .lines()
        .map(str::trim)
        .find(|line| line.starts_with("SAW_") || *line == "DENIED")
        .unwrap_or_else(|| panic!("no call result from {}:\n{output}", sandbox.name))
        .to_string()
}

async fn delete_until_gone(args: &[&str]) {
    for _ in 0..40 {
        let (deleted, output) = cli(args).await;
        if deleted || output.to_lowercase().contains("not found") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    eprintln!("'{}' did not settle", args.join(" "));
}

async fn remove_providers() {
    for name in [ALPHA, BETA] {
        delete_until_gone(&["provider", "delete", name]).await;
        delete_until_gone(&["profile", "delete", name]).await;
    }
}

/// Install provider `name`, of a profile with the same name, holding `secret`
/// for `port`.
async fn install_provider(name: &str, port: u16, secret: &str) {
    let profile = profile(name, port);
    let (imported, output) = cli(&[
        "profile",
        "import",
        "--file",
        profile.path().to_str().expect("UTF-8 profile path"),
    ])
    .await;
    assert!(imported, "profile import {name} failed:\n{output}");
    let credential = format!("{TOKEN_ENV}={secret}");
    let (created, output) = cli(&[
        "provider",
        "create",
        "--name",
        name,
        "--type",
        name,
        "--credential",
        &credential,
    ])
    .await;
    assert!(created, "provider create {name} failed:\n{output}");
}

/// Bound on the shared supervisor answering a routed connection: its own
/// handshake deadline is 5 s.
const PROBE_DEADLINE: Duration = Duration::from_secs(10);

/// What the shared supervisor did with a connection that named a route.
#[derive(Debug, PartialEq, Eq)]
enum RouteAnswer {
    /// Closed or reset the connection before sending anything.
    Refused,
    /// Started the TLS handshake for the route's pinned identity; the first
    /// bytes it sent.
    Challenged(Vec<u8>),
}

/// A connection closed or reset by the peer.
fn is_closed(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::UnexpectedEof
    )
}

/// Port-forward to the shared supervisor's routed runtime listener.
struct RuntimeListener {
    child: tokio::process::Child,
    port: u16,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl RuntimeListener {
    async fn forward() -> Self {
        let service = format!(
            "svc/{}-supervisor",
            std::env::var("OPENSHELL_E2E_KUBE_RELEASE").unwrap_or_else(|_| "openshell".into())
        );
        let mut child = kubectl_command()
            .args([
                "-n",
                &release_namespace(),
                "port-forward",
                &service,
                &format!(":{RUNTIME_PORT}"),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn kubectl port-forward");
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let mut errors = tokio::io::BufReader::new(child.stderr.take().expect("stderr")).lines();
        let recorded = stderr.clone();
        tokio::spawn(async move {
            while let Ok(Some(line)) = errors.next_line().await {
                recorded.lock().unwrap().push(line);
            }
        });
        let mut lines = tokio::io::BufReader::new(child.stdout.take().expect("stdout")).lines();
        let port = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = lines.next_line().await.expect("read port-forward") {
                // "Forwarding from 127.0.0.1:43127 -> 5500"
                if let Some(port) = line
                    .strip_prefix("Forwarding from 127.0.0.1:")
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|port| port.parse().ok())
                {
                    return port;
                }
            }
            panic!("port-forward ended before it was ready");
        })
        .await
        .expect("port-forward ready");
        // kubectl reports every forwarded connection on stdout and exits if
        // that pipe closes.
        tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
        Self {
            child,
            port,
            stderr,
        }
    }

    /// Every connection reached the supervisor Pod: kubectl reports a failed
    /// pod-side dial on stderr, and the local side then sees the same EOF as a
    /// refusal.
    async fn assert_forwarded_every_connection(&mut self) {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let failed = self.stderr.lock().unwrap().iter().any(|line| {
            line.contains("an error occurred forwarding") || line.contains("error forwarding port")
        });
        assert!(
            !failed,
            "a probe never reached the supervisor; {}",
            self.diagnostics()
        );
    }

    /// The forwarder's state, for failure messages.
    fn diagnostics(&mut self) -> String {
        format!(
            "kubectl port-forward status {:?}, stderr {:?}",
            self.child.try_wait(),
            self.stderr.lock().unwrap()
        )
    }

    /// Name `route` in a routing preface and report how the supervisor
    /// answered. A challenged connection is then sent `reply` in place of the
    /// pinned TLS identity and must be closed. Silence fails the test: a
    /// listener that hangs has not rejected anything.
    async fn probe(&mut self, route: &str, reply: &[u8]) -> RouteAnswer {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port))
            .await
            .expect("connect to forwarded runtime listener");
        let mut preface = b"OSRP\x01".to_vec();
        preface.push(u8::try_from(route.len()).expect("route length"));
        preface.extend_from_slice(route.as_bytes());
        stream.write_all(&preface).await.expect("send preface");
        let mut answer = vec![0_u8; 5];
        let read = match tokio::time::timeout(PROBE_DEADLINE, stream.read(&mut answer)).await {
            Ok(Ok(read)) => read,
            Ok(Err(error)) if is_closed(&error) => 0,
            Ok(Err(error)) => panic!("read the answer to route {route}: {error}"),
            Err(elapsed) => panic!(
                "route {route} was neither refused nor challenged ({elapsed}, {PROBE_DEADLINE:?}); {}",
                self.diagnostics()
            ),
        };
        if read == 0 {
            return RouteAnswer::Refused;
        }
        answer.truncate(read);
        if let Err(error) = stream.write_all(reply).await {
            assert!(is_closed(&error), "answer route {route}: {error}");
        }
        let mut rest = Vec::new();
        match tokio::time::timeout(PROBE_DEADLINE, stream.read_to_end(&mut rest)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) if is_closed(&error) => {}
            Ok(Err(error)) => panic!("wait for route {route} to close: {error}"),
            Err(elapsed) => panic!(
                "route {route} stayed open without its pinned TLS identity ({elapsed}, {PROBE_DEADLINE:?}); {}",
                self.diagnostics()
            ),
        }
        RouteAnswer::Challenged(answer)
    }
}

impl Drop for RuntimeListener {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// A fatal TLS `handshake_failure` alert: a peer without the pinned identity.
const TLS_HANDSHAKE_FAILURE: &[u8] = b"\x15\x03\x03\x00\x02\x02\x28";
const TLS_HANDSHAKE_RECORD: u8 = 0x16;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn one_supervisor_isolates_and_outlives_concurrent_sandbox_instances() {
    let nonce = format!("{:08x}", rand::random::<u32>());
    let (alpha_secret, beta_secret) = (format!("alpha-{nonce}"), format!("beta-{nonce}"));
    let alpha_endpoint = CredentialEndpoint::start(&alpha_secret, &beta_secret).await;
    let beta_endpoint = CredentialEndpoint::start(&alpha_secret, &beta_secret).await;
    let plain_endpoint = CredentialEndpoint::start(&alpha_secret, &beta_secret).await;
    remove_providers().await;
    install_provider(ALPHA, alpha_endpoint.port, &alpha_secret).await;
    install_provider(BETA, beta_endpoint.port, &beta_secret).await;
    let (supervisor_uid, supervisor_restarts) = shared_supervisor_pod().await;

    // Only alpha's own policy allows the plain endpoint.
    let alpha_policy = policy(&[alpha_endpoint.port, plain_endpoint.port]);
    let beta_policy = policy(&[beta_endpoint.port]);
    let keep = ["sh", "-c", "echo shared-ready; exec sleep infinity"];
    let create = |policy: &NamedTempFile, provider: &str| {
        let policy = policy
            .path()
            .to_str()
            .expect("UTF-8 policy path")
            .to_string();
        let provider = provider.to_string();
        async move {
            SandboxGuard::create_keep_with_args(
                &["--policy", &policy, "--provider", &provider],
                &keep,
                "shared-ready",
            )
            .await
        }
    };
    let (alpha, beta) = tokio::join!(create(&alpha_policy, ALPHA), create(&beta_policy, BETA));
    let mut alpha = alpha.expect("create alpha sandbox");
    let mut beta = beta.expect("create beta sandbox");

    // Both generations are sandbox instances on the one shared supervisor
    // process.
    let alpha_route = instance_route(&alpha.name).await;
    let beta_route = instance_route(&beta.name).await;
    assert_ne!(alpha_route, beta_route);
    assert_no_dedicated_supervisors().await;
    assert_eq!(shared_supervisor_pod().await.0, supervisor_uid);

    // Each instance injects only its own credential and enforces only its own
    // policy, including the endpoint its own provider contributes.
    assert_eq!(call(&alpha, alpha_endpoint.port).await, "SAW_ALPHA");
    assert_eq!(call(&beta, beta_endpoint.port).await, "SAW_BETA");
    assert_eq!(call(&alpha, beta_endpoint.port).await, "DENIED");
    assert_eq!(call(&beta, alpha_endpoint.port).await, "DENIED");
    assert_eq!(
        call_with(&alpha, plain_endpoint.port, false).await,
        "SAW_OTHER"
    );
    assert_eq!(call_with(&beta, plain_endpoint.port, false).await, "DENIED");
    assert_eq!(alpha_endpoint.seen(), [Seen::Alpha]);
    assert_eq!(beta_endpoint.seen(), [Seen::Beta]);
    assert_eq!(plain_endpoint.seen(), [Seen::Other]);

    // Stopping alpha removes only its sandbox instance.
    let (stopped, output) = cli(&["sandbox", "stop", &alpha.name]).await;
    assert!(stopped, "sandbox stop failed:\n{output}");
    assert_eq!(call(&beta, beta_endpoint.port).await, "SAW_BETA");

    // A peer naming a live route must present that instance's pinned TLS
    // identity, and failing to does not displace the instance. Stale and
    // unknown routes are refused before any handshake.
    let mut listener = RuntimeListener::forward().await;
    for _ in 0..3 {
        match listener.probe(&beta_route, TLS_HANDSHAKE_FAILURE).await {
            RouteAnswer::Challenged(answer) => assert_eq!(
                answer.first(),
                Some(&TLS_HANDSHAKE_RECORD),
                "a live route should start the instance's pinned TLS handshake"
            ),
            RouteAnswer::Refused => {
                panic!("a live route should demand the instance's pinned TLS identity")
            }
        }
    }
    assert_eq!(
        listener.probe(&alpha_route, &[]).await,
        RouteAnswer::Refused,
        "stale route reached a sandbox instance"
    );
    let unknown = format!("rt-{:032x}", rand::random::<u128>());
    assert_eq!(
        listener.probe(&unknown, &[]).await,
        RouteAnswer::Refused,
        "unknown route reached a sandbox instance"
    );
    assert!(matches!(
        listener.probe(&beta_route, TLS_HANDSHAKE_FAILURE).await,
        RouteAnswer::Challenged(_)
    ));
    listener.assert_forwarded_every_connection().await;
    drop(listener);
    assert_eq!(call(&beta, beta_endpoint.port).await, "SAW_BETA");

    // Restarting alpha registers a fresh sandbox instance on the same process.
    let (started, output) = cli(&["sandbox", "start", &alpha.name]).await;
    assert!(started, "sandbox start failed:\n{output}");
    let restarted_route = instance_route(&alpha.name).await;
    assert_ne!(restarted_route, alpha_route);
    let restarted_call = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            match alpha
                .exec(&["python3", "-c", &call_script(alpha_endpoint.port, true)])
                .await
            {
                Ok(output) if output.contains("SAW_ALPHA") => return,
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
    })
    .await;
    assert!(
        restarted_call.is_ok(),
        "restarted alpha never regained supervision"
    );
    assert_eq!(call(&beta, beta_endpoint.port).await, "SAW_BETA");
    let mut listener = RuntimeListener::forward().await;
    assert_eq!(
        listener.probe(&alpha_route, &[]).await,
        RouteAnswer::Refused,
        "the replaced route reached a sandbox instance"
    );
    assert!(matches!(
        listener
            .probe(&restarted_route, TLS_HANDSHAKE_FAILURE)
            .await,
        RouteAnswer::Challenged(_)
    ));
    listener.assert_forwarded_every_connection().await;
    drop(listener);

    assert_eq!(
        shared_supervisor_pod().await,
        (supervisor_uid, supervisor_restarts),
        "the shared supervisor must keep running throughout"
    );
    assert_no_dedicated_supervisors().await;
    alpha.cleanup().await;
    beta.cleanup().await;
    remove_providers().await;
}
