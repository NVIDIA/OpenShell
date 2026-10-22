// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor-spiffe")]

//! Sandbox identities delegated by SPIRE to the shared supervisor.
//!
//! The wrapper installs SPIRE (`ci/values-spire-delegation-stack.yaml`) and
//! the gateway topology with SPIRE delegation
//! (`ci/values-supervisor-spiffe.yaml`). This test registers
//! sandbox identities as an operator would, with `ClusterStaticEntry`
//! resources, and drives the existing RFC 8693 provider exchange: the gateway
//! exchanges the stored subject token with its own SVID for the sandbox's
//! SPIFFE ID, and the shared supervisor exchanges that intermediate token with
//! the sandbox's delegated SVID. The token service is a host fixture reached
//! through a selectorless Service, and it hands out tokens that name the
//! identity they were issued to.

use std::collections::HashMap;
use std::io::Write as _;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const TEST_HOST: &str = "host.openshell.internal";
/// Matches `ci/values-spire-delegation-stack.yaml`.
const TRUST_DOMAIN: &str = "openshell.local";
const SPIRE_CLUSTER: &str = "openshell-e2e";
/// Matches `ci/values-supervisor-spiffe.yaml`.
const ID_PREFIX: &str = "spiffe://openshell.local/openshell";
/// Label on the registration entries this run creates, naming its SPIRE
/// fixture so cleanup never touches another run's entries.
const ENTRY_LABEL: &str = "openshell.ai/e2e-spire-fixture";
const STS_SERVICE: &str = "openshell-e2e-sts";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";
const TOPOLOGY_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-topology";
/// Instance route annotation; the key keeps its established `-session` name.
const INSTANCE_ROUTE_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-session";

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

async fn kubectl_with_input(args: &[&str], input: Option<&str>) -> String {
    let mut child = kubectl_command()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("spawn kubectl {args:?}: {error}"));
    let mut stdin = child.stdin.take().expect("kubectl stdin");
    if let Some(input) = input {
        stdin
            .write_all(input.as_bytes())
            .await
            .expect("write kubectl input");
    }
    drop(stdin);
    let output = child.wait_with_output().await.expect("wait for kubectl");
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn kubectl(args: &[&str]) -> String {
    kubectl_with_input(args, None).await
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

fn spiffe_id(gateway_id: &str, sandbox_id: &str) -> String {
    format!("{ID_PREFIX}/gateway/{gateway_id}/sandbox/{sandbox_id}")
}

/// Claims of a JWT, decoded for observation only.
fn claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap_or_default();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// One exchange the token service answered.
#[derive(Clone, Debug)]
struct Exchange {
    /// Subject of the client assertion.
    assertion_subject: String,
    /// `audience` parameter of the request.
    audience: String,
    /// Whether the subject token was the stored user token (the gateway's
    /// intermediate exchange) rather than an intermediate token.
    intermediate: bool,
}

/// RFC 8693 token service that binds each intermediate token to the SPIFFE ID
/// it was issued for, and issues a final token only to that identity.
struct TokenService {
    port: u16,
    state: Arc<Mutex<TokenState>>,
    task: tokio::task::JoinHandle<()>,
}

#[derive(Default)]
struct TokenState {
    exchanges: Vec<Exchange>,
    /// Intermediate token -> the SPIFFE ID it was issued for.
    intermediates: HashMap<String, String>,
}

impl TokenService {
    async fn start(stored_token: String) -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind token service");
        let port = listener.local_addr().expect("token service address").port();
        let state = Arc::new(Mutex::new(TokenState::default()));
        let (shared, stored) = (state.clone(), Arc::new(stored_token));
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (state, stored) = (shared.clone(), stored.clone());
                tokio::spawn(async move {
                    let _ = answer_token_request(stream, &state, &stored).await;
                });
            }
        });
        Self { port, state, task }
    }

    fn exchanges(&self) -> Vec<Exchange> {
        self.state.lock().unwrap().exchanges.clone()
    }
}

impl Drop for TokenService {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_request(stream: &mut TcpStream) -> std::io::Result<(String, String)> {
    let mut request = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&request);
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if body.len() >= length {
                return Ok((head.to_string(), body.to_string()));
            }
        }
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    Ok(text
        .split_once("\r\n\r\n")
        .map(|(head, body)| (head.to_string(), body.to_string()))
        .unwrap_or((text, String::new())))
}

fn form(body: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect()
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await
}

async fn answer_token_request(
    mut stream: TcpStream,
    state: &Mutex<TokenState>,
    stored: &str,
) -> std::io::Result<()> {
    let (_, body) = read_request(&mut stream).await?;
    let fields = form(&body);
    let field = |name: &str| fields.get(name).cloned().unwrap_or_default();
    let assertion_subject = claims(&field("client_assertion"))["sub"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let well_formed = field("grant_type") == "urn:ietf:params:oauth:grant-type:token-exchange"
        && field("client_assertion_type") == CLIENT_ASSERTION_TYPE
        && field("subject_token_type") == TOKEN_TYPE_ACCESS_TOKEN
        && assertion_subject.starts_with("spiffe://");
    let issued = {
        let mut state = state.lock().unwrap();
        let subject_token = field("subject_token");
        let audience = field("audience");
        if !well_formed {
            None
        } else if subject_token == stored {
            // The gateway exchanges the user's token for the sandbox identity
            // named in `audience`.
            let token = format!("intermediate-{}", state.intermediates.len() + 1);
            state.intermediates.insert(token.clone(), audience.clone());
            state.exchanges.push(Exchange {
                assertion_subject,
                audience,
                intermediate: true,
            });
            Some(token)
        } else if state.intermediates.get(&subject_token) == Some(&assertion_subject) {
            // Only the identity an intermediate token names may redeem it.
            let sandbox = assertion_subject.rsplit('/').next().unwrap_or_default();
            let token = format!("final-{sandbox}-{}", state.exchanges.len() + 1);
            state.exchanges.push(Exchange {
                assertion_subject,
                audience,
                intermediate: false,
            });
            Some(token)
        } else {
            None
        }
    };
    match issued {
        Some(token) => {
            let body = format!(
                r#"{{"access_token":"{token}","issued_token_type":"{TOKEN_TYPE_ACCESS_TOKEN}","token_type":"Bearer","expires_in":300}}"#
            );
            respond(&mut stream, "200 OK", &body).await
        }
        None => {
            respond(
                &mut stream,
                "400 Bad Request",
                r#"{"error":"invalid_grant"}"#,
            )
            .await
        }
    }
}

/// Protected endpoint that reports which sandbox a final token was issued to.
struct Target {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl Target {
    async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind protected target");
        let port = listener.local_addr().expect("target address").port();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let Ok((head, _)) = read_request(&mut stream).await else {
                        return;
                    };
                    let authorization = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("authorization")
                                .then(|| value.trim().to_string())
                        })
                        .unwrap_or_default();
                    // "Bearer final-<sandbox-id>-<n>" -> "SAW:<sandbox-id>"
                    let seen = authorization
                        .strip_prefix("Bearer final-")
                        .and_then(|rest| rest.rsplit_once('-'))
                        .map_or_else(|| "SAW:NONE".to_string(), |(id, _)| format!("SAW:{id}"));
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{seen}",
                        seen.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { port, task }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A selectorless Service in front of the host token service, so token
/// endpoints are the in-cluster `http://<service>.<namespace>.svc` URLs that
/// gateways and supervisors accept without TLS.
async fn expose_token_service(port: u16) -> String {
    let host_ip = std::env::var("OPENSHELL_E2E_HOST_GATEWAY_IP")
        .ok()
        .filter(|ip| !ip.is_empty())
        .expect("OPENSHELL_E2E_HOST_GATEWAY_IP is set by with-kube-gateway.sh");
    let namespace = release_namespace();
    let manifest = format!(
        r"apiVersion: v1
kind: Service
metadata:
  name: {STS_SERVICE}
  namespace: {namespace}
spec:
  ports:
    - name: http
      port: 80
      targetPort: {port}
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: {STS_SERVICE}
  namespace: {namespace}
  labels:
    kubernetes.io/service-name: {STS_SERVICE}
addressType: IPv4
ports:
  - name: http
    port: {port}
endpoints:
  - addresses: [{host_ip}]
"
    );
    kubectl_with_input(&["apply", "-f", "-"], Some(&manifest)).await;
    format!("http://{STS_SERVICE}.{namespace}.svc.cluster.local/token")
}

async fn remove_token_service() {
    let namespace = release_namespace();
    let _ = kubectl_command()
        .args([
            "-n",
            &namespace,
            "delete",
            "service,endpointslice",
            STS_SERVICE,
            "--ignore-not-found",
        ])
        .output()
        .await;
}

/// A provider profile whose bearer credential comes from the existing RFC
/// 8693 exchange, bound to `target_port` on the test host.
fn profile(id: &str, token_endpoint: &str, target_port: u16) -> NamedTempFile {
    temp_yaml(&format!(
        r"id: {id}
display_name: E2E delegated sandbox identity
description: Token exchange with the sandbox's SPIRE-delegated SVID
category: other
credentials:
  - name: subject_token
    description: Stored user subject token
    required: true
  - name: access_token
    description: Access token obtained through token exchange
    required: false
    auth_style: bearer
    header_name: Authorization
    token_grant:
      grant_type: token_exchange
      token_endpoint: {token_endpoint}
      audience: e2e-service
      jwt_svid_audience: {token_endpoint}
      client_assertion_type: {CLIENT_ASSERTION_TYPE}
      requested_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
      cache_ttl_seconds: 300
      subject_token:
        source: provider_credential
        credential: subject_token
        subject_token_type: {TOKEN_TYPE_ACCESS_TOKEN}
endpoints:
  - host: {TEST_HOST}
    port: {target_port}
    path: /**
    protocol: rest
    access: read-write
    enforcement: enforce
    allowed_ips:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
binaries:
  - /**
"
    ))
}

/// What the sandbox saw calling the protected target: `SAW:<sandbox-id>`,
/// `DENIED` for a refused grant, or a failure description.
fn call_script(port: u16) -> String {
    format!(
        r#"
import urllib.error, urllib.request, uuid

try:
    with urllib.request.urlopen("http://{TEST_HOST}:{port}/resource", timeout=20) as response:
        print(response.read().decode())
except urllib.error.HTTPError as error:
    request_id = error.headers.get("x-openshell-request-id", "")
    if error.code == 502 and str(uuid.UUID(request_id)) == request_id:
        print("DENIED")
    else:
        print(f"HTTP-{{error.code}}")
except OSError:
    print("UNREACHABLE")
"#
    )
}

async fn call(sandbox: &SandboxGuard, port: u16) -> String {
    let output = sandbox
        .exec(&["python3", "-c", &call_script(port)])
        .await
        .unwrap_or_else(|error| panic!("call from {}: {error}", sandbox.name));
    output
        .lines()
        .map(str::trim)
        .find(|line| {
            line.starts_with("SAW:")
                || *line == "DENIED"
                || line.starts_with("HTTP-")
                || *line == "UNREACHABLE"
        })
        .unwrap_or_else(|| panic!("no call result from {}:\n{output}", sandbox.name))
        .to_string()
}

/// Call until the sandbox sees `expected`, as SPIRE propagates a new entry to
/// its agent and a restarted sandbox instance becomes ready.
async fn call_until(sandbox: &SandboxGuard, port: u16, expected: &str) {
    let mut last = String::new();
    let reached = tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            last = call(sandbox, port).await;
            if last == expected {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "{} never saw {expected}; last saw {last}",
        sandbox.name
    );
}

/// The Sandbox resource of an `OpenShell` sandbox.
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

async fn sandbox_id(name: &str) -> String {
    let (ok, output) = cli(&["sandbox", "get", name, "--output", "json"]).await;
    assert!(ok, "sandbox get {name} failed:\n{output}");
    let details: serde_json::Value = serde_json::from_str(&output).expect("parse sandbox JSON");
    details["id"].as_str().expect("sandbox id").to_string()
}

/// The shared-supervisor sandbox instance route of a sandbox's current
/// generation.
async fn instance_route(name: &str) -> String {
    let resource = sandbox_resource(name).await;
    let annotations = &resource["metadata"]["annotations"];
    assert_eq!(annotations[TOPOLOGY_ANNOTATION], "gateway");
    annotations[INSTANCE_ROUTE_ANNOTATION]
        .as_str()
        .expect("sandbox instance route")
        .to_string()
}

/// Gateway ID the gateway signs session JWTs with.
async fn gateway_id() -> String {
    let output = kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "configmaps",
        "-o",
        "jsonpath={.items[*].data.gateway\\.toml}",
    ])
    .await;
    output
        .lines()
        .find_map(|line| {
            let value = line.trim().strip_prefix("gateway_id = \"")?;
            value.strip_suffix('"').map(str::to_string)
        })
        .expect("gateway_id in gateway TOML")
}

/// SPIRE agent ID of the node running the gateway.
async fn gateway_agent_id() -> String {
    let node = kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        "app.kubernetes.io/name=openshell,app.kubernetes.io/instance=openshell",
        "-o",
        "jsonpath={.items[0].spec.nodeName}",
    ])
    .await;
    let uid = kubectl(&["get", "node", node.trim(), "-o", "jsonpath={.metadata.uid}"]).await;
    format!(
        "spiffe://{TRUST_DOMAIN}/spire/agent/k8s_psat/{SPIRE_CLUSTER}/{}",
        uid.trim()
    )
}

fn spire_fixture() -> String {
    std::env::var("OPENSHELL_E2E_SPIRE_NAMESPACE")
        .ok()
        .filter(|namespace| !namespace.is_empty())
        .expect("OPENSHELL_E2E_SPIRE_NAMESPACE is set by with-kube-gateway.sh")
}

/// Register `sandbox_id`'s SPIFFE ID for delegation, scoped to `agent_id`.
async fn register(gateway_id: &str, sandbox_id: &str, agent_id: &str) {
    let fixture = spire_fixture();
    // The SPIRE Controller Manager's class is `<namespace>-<release>`; the
    // wrapper installs release `spire` in the fixture namespace.
    let class_name = format!("{fixture}-spire");
    let manifest = format!(
        r"apiVersion: spire.spiffe.io/v1alpha1
kind: ClusterStaticEntry
metadata:
  name: openshell-sandbox-{sandbox_id}
  labels:
    {ENTRY_LABEL}: {fixture}
spec:
  className: {class_name}
  spiffeID: {}
  parentID: {agent_id}
  selectors:
    - openshell:sandbox:{gateway_id}:{sandbox_id}
",
        spiffe_id(gateway_id, sandbox_id)
    );
    kubectl_with_input(&["apply", "-f", "-"], Some(&manifest)).await;
}

async fn unregister_all() {
    let _ = kubectl_command()
        .args([
            "delete",
            "clusterstaticentries.spire.spiffe.io",
            "-l",
            &format!("{ENTRY_LABEL}={}", spire_fixture()),
            "--ignore-not-found",
        ])
        .output()
        .await;
}

// Inspect access-bearing fields. Image tags and node names may legitimately
// contain "spiffe" without exposing an identity socket or credential.
fn assert_no_spiffe_access(pod: &serde_json::Value) {
    let spec = &pod["spec"];
    let containers = spec["containers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|container| {
            serde_json::json!({
                "env": container["env"],
                "mounts": container["volumeMounts"],
                "args": container["args"],
            })
        })
        .collect::<Vec<_>>();
    let access = serde_json::json!({ "volumes": spec["volumes"], "containers": containers })
        .to_string()
        .to_lowercase();
    assert!(
        !access.contains("spiffe") && !access.contains("spire"),
        "Pod {} carries SPIFFE access",
        pod["metadata"]["name"]
    );
}

/// No sandbox workload Pod receives a SPIFFE socket, SPIRE mount, or SPIFFE
/// environment.
async fn assert_workloads_hold_no_spiffe_material() {
    let output = kubectl(&[
        "get",
        "pods",
        "--all-namespaces",
        "-l",
        "openshell.ai/boundary-role=workload",
        "-o",
        "json",
    ])
    .await;
    let pods: serde_json::Value = serde_json::from_str(&output).expect("parse workload Pods");
    let items = pods["items"].as_array().expect("Pod items");
    assert!(!items.is_empty(), "no sandbox workload Pods found");
    for pod in items {
        assert_no_spiffe_access(pod);
    }
}

/// Inside the sandbox: no SPIFFE socket, environment, or SVID.
async fn assert_sandbox_holds_no_spiffe_material(sandbox: &SandboxGuard) {
    let script = r#"
import base64, json, os, re
leaks = [name for name in os.environ if "SPIFFE" in name.upper() or "SPIRE" in name.upper()]
leaks += [path for path in ("/spiffe-workload-api", "/run/spire", "/tmp/spire-agent") if os.path.exists(path)]
for value in os.environ.values():
    for token in re.findall(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", value):
        try:
            payload = token.split(".")[1]
            claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        except (ValueError, UnicodeError):
            continue
        if str(claims.get("sub", "")).startswith("spiffe://openshell.local/"):
            leaks.append("svid-in-environment")
print("LEAKS:" + ",".join(leaks) if leaks else "NO-SPIFFE")
"#;
    let output = sandbox
        .exec(&["python3", "-c", script])
        .await
        .unwrap_or_else(|error| panic!("inspect {}: {error}", sandbox.name));
    assert!(
        output.lines().any(|line| line.trim() == "NO-SPIFFE"),
        "{} holds SPIFFE material:\n{output}",
        sandbox.name
    );
}

async fn create(name: &str, provider: &str) -> SandboxGuard {
    SandboxGuard::create_keep_with_args(
        &["--name", name, "--provider", provider],
        &["sh", "-c", "echo spiffe-ready; exec sleep infinity"],
        "spiffe-ready",
    )
    .await
    .unwrap_or_else(|error| panic!("create {name}: {error}"))
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn shared_supervisor_acts_as_each_sandboxs_stable_spiffe_identity() {
    let nonce = format!("{:08x}", rand::random::<u32>());
    let stored_token = format!("stored-{nonce}");
    let tokens = TokenService::start(stored_token.clone()).await;
    let target = Target::start().await;
    let token_endpoint = expose_token_service(tokens.port).await;
    let provider = format!("e2e-spiffe-{nonce}");
    let profile = profile(&provider, &token_endpoint, target.port);
    let (imported, output) = cli(&[
        "profile",
        "import",
        "--file",
        profile.path().to_str().expect("UTF-8 profile path"),
    ])
    .await;
    assert!(imported, "profile import failed:\n{output}");
    let credential = format!("subject_token={stored_token}");
    let (created, output) = cli(&[
        "provider",
        "create",
        "--name",
        &provider,
        "--type",
        &provider,
        "--credential",
        &credential,
    ])
    .await;
    assert!(created, "provider create failed:\n{output}");

    // Sandbox names are limited to 19 characters.
    let (alpha_name, beta_name) = (format!("spa-{nonce}"), format!("spb-{nonce}"));
    let (alpha, beta) = tokio::join!(
        create(&alpha_name, &provider),
        create(&beta_name, &provider)
    );
    let (mut alpha, mut beta) = (alpha, beta);
    let gateway_id = gateway_id().await;
    let agent_id = gateway_agent_id().await;
    let alpha_id = sandbox_id(&alpha.name).await;
    let beta_id = sandbox_id(&beta.name).await;

    // Without a registration entry the shared supervisor has no identity to
    // act as, and never falls back to its own.
    assert_eq!(call(&alpha, target.port).await, "DENIED");
    assert!(tokens.exchanges().is_empty());

    // Each sandbox exchanges under its own stable SPIFFE ID.
    register(&gateway_id, &alpha_id, &agent_id).await;
    register(&gateway_id, &beta_id, &agent_id).await;
    call_until(&alpha, target.port, &format!("SAW:{alpha_id}")).await;
    call_until(&beta, target.port, &format!("SAW:{beta_id}")).await;
    let finals = |exchanges: &[Exchange]| {
        exchanges
            .iter()
            .filter(|exchange| !exchange.intermediate)
            .map(|exchange| exchange.assertion_subject.clone())
            .collect::<Vec<_>>()
    };
    let exchanges = tokens.exchanges();
    assert_eq!(
        finals(&exchanges),
        [
            spiffe_id(&gateway_id, &alpha_id),
            spiffe_id(&gateway_id, &beta_id)
        ]
    );
    // The gateway asked for intermediate tokens for exactly those identities,
    // with its own identity rather than a sandbox's.
    for exchange in exchanges.iter().filter(|exchange| exchange.intermediate) {
        assert!(
            [
                spiffe_id(&gateway_id, &alpha_id),
                spiffe_id(&gateway_id, &beta_id)
            ]
            .contains(&exchange.audience),
            "unexpected intermediate audience {exchange:?}"
        );
        assert!(
            !exchange.assertion_subject.starts_with(ID_PREFIX),
            "gateway presented a sandbox identity: {exchange:?}"
        );
    }
    let shared_pods = kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        "app.kubernetes.io/component=supervisor",
        "-o",
        "json",
    ])
    .await;
    let shared: serde_json::Value = serde_json::from_str(&shared_pods).unwrap();
    for pod in shared["items"].as_array().unwrap() {
        assert_no_spiffe_access(pod);
    }
    assert_workloads_hold_no_spiffe_material().await;
    assert_sandbox_holds_no_spiffe_material(&alpha).await;
    assert_sandbox_holds_no_spiffe_material(&beta).await;

    // A restart is a new generation with a new sandbox instance and an empty
    // cache, and it acquires under the same SPIFFE ID.
    let alpha_route = instance_route(&alpha.name).await;
    let (stopped, output) = cli(&["sandbox", "stop", &alpha.name]).await;
    assert!(stopped, "sandbox stop failed:\n{output}");
    let (started, output) = cli(&["sandbox", "start", &alpha.name]).await;
    assert!(started, "sandbox start failed:\n{output}");
    assert_ne!(instance_route(&alpha.name).await, alpha_route);
    let before_restart = finals(&tokens.exchanges()).len();
    call_until(&alpha, target.port, &format!("SAW:{alpha_id}")).await;
    let after_restart = finals(&tokens.exchanges());
    assert!(
        after_restart.len() > before_restart,
        "the restarted generation reused an earlier generation's token"
    );
    assert!(
        after_restart[before_restart..]
            .iter()
            .all(|subject| *subject == spiffe_id(&gateway_id, &alpha_id))
    );
    assert_eq!(call(&beta, target.port).await, format!("SAW:{beta_id}"));

    // A sandbox recreated under the same name is a new sandbox with a new
    // identity; the old registration does not apply to it.
    alpha.cleanup().await;
    let mut recreated = create(&alpha_name, &provider).await;
    let recreated_id = sandbox_id(&recreated.name).await;
    assert_ne!(recreated_id, alpha_id);
    let before_recreate = tokens.exchanges().len();
    assert_eq!(call(&recreated, target.port).await, "DENIED");
    assert_eq!(tokens.exchanges().len(), before_recreate);
    register(&gateway_id, &recreated_id, &agent_id).await;
    call_until(&recreated, target.port, &format!("SAW:{recreated_id}")).await;
    assert_eq!(
        finals(&tokens.exchanges()).last(),
        Some(&spiffe_id(&gateway_id, &recreated_id))
    );
    assert_sandbox_holds_no_spiffe_material(&recreated).await;

    // Identifiers only: the exchanges' tokens are never printed.
    for exchange in tokens.exchanges() {
        eprintln!(
            "token exchange: intermediate={} assertion_subject={} audience={}",
            exchange.intermediate, exchange.assertion_subject, exchange.audience
        );
    }

    recreated.cleanup().await;
    beta.cleanup().await;
    let _ = cli(&["provider", "delete", &provider]).await;
    let _ = cli(&["profile", "delete", &provider]).await;
    unregister_all().await;
    remove_token_service().await;
}
