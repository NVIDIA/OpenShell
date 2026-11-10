// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers shared by the shared supervisor pool tests: the release's
//! Kubernetes objects, which pool member supervises a sandbox, and the
//! sandbox workload whose main process counts in memory.
//!
//! Each test binary uses a subset.
#![allow(dead_code)]

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

pub const TEST_HOST: &str = "host.openshell.internal";
pub const SUPERVISOR_COMPONENT: &str = "app.kubernetes.io/component=supervisor";
const INSTANCE_ROUTE_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
const GENERATION_ANNOTATION: &str = "openshell.ai/sandbox-runtime-generation";
/// The workload's main process: it records its PID once and a counter that
/// lives only in its memory every second. A restarted process would start
/// counting from one again.
pub const COUNTER_MAIN: &str = "echo $$ > /tmp/ha-main.pid; i=0; while true; do i=$((i+1)); echo $i > /tmp/ha-counter; sleep 1; done";
/// Gateway Pods of the release: the chart's selector labels name the gateway
/// `openshell`, while the supervisor and certgen Pods carry their own names.
pub const GATEWAY_SELECTOR: &str = "app.kubernetes.io/name=openshell";
pub const GATEWAY_CONTAINER: &str = "openshell-gateway";
pub const SUPERVISOR_CONTAINER: &str = "supervisor";
/// What the gateway logs when it moves an instance to another member.
pub const TAKEOVER: &str = "taking over a shared sandbox instance from a failed supervisor";
/// Supervisor lines that change which member supervises a route; each names
/// the route in its text after the phrase. They must match the messages in
/// `crates/openshell-supervisor/src/shared_host.rs`.
const ADMITTED: &str = "admitted assigned sandbox instance";
const RELEASES: [&str; 3] = [
    "removing withdrawn sandbox instance",
    "relinquishing a sandbox instance owned by another pool member",
    "relinquishing a sandbox instance for its later ownership term",
];
/// What a supervisor logs when the gateway accepts its stream, and when any
/// stream ends; the later of the two says whether it is attached now.
const ATTACHED: &str = "gateway accepted the supervisor host";
const DETACHED: &str = "gateway assignment stream lost";
/// Bound on a supervisor attaching to the gateway. A Pod is TCP-ready before
/// it can authenticate: on a fresh install the gateway writes the supervisor
/// token into the chart's initially empty Secret, and the kubelet projects
/// the update into the Pod only after its sync period (about 90 s observed).
pub const ATTACH_TIMEOUT: Duration = Duration::from_mins(3);
/// After a member attaches, the gateway writes its membership record within
/// two bounded refresh rounds (2 x 500 ms); placement reads that record.
const MEMBERSHIP_RECORD_BOUND: Duration = Duration::from_secs(2);
/// Bound on one exec probe of a sandbox, so a hung CLI cannot stall a test.
pub const EXEC_PROBE_TIMEOUT: Duration = Duration::from_secs(20);
/// Bound on one policy-mediated network probe from a sandbox.
pub const NETWORK_PROBE_TIMEOUT: Duration = Duration::from_secs(40);

pub fn release_namespace() -> String {
    std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE").unwrap_or_else(|_| "openshell".to_string())
}

/// The kubeconfig and context the harness uses, when it names them.
fn kube_target() -> (Option<String>, Option<String>) {
    let set = |name: &str| {
        std::env::var(name)
            .ok()
            .filter(|value| !value.trim().is_empty())
    };
    (
        set("OPENSHELL_E2E_KUBECONFIG"),
        set("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE"),
    )
}

pub fn kubectl_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("kubectl");
    let (kubeconfig, context) = kube_target();
    if let Some(kubeconfig) = kubeconfig {
        command.arg("--kubeconfig").arg(kubeconfig);
    }
    if let Some(context) = context {
        command.arg("--context").arg(context);
    }
    command.stdin(Stdio::null()).kill_on_drop(true);
    command
}

pub fn helm_command() -> tokio::process::Command {
    let mut command = tokio::process::Command::new("helm");
    let (kubeconfig, context) = kube_target();
    if let Some(kubeconfig) = kubeconfig {
        command.arg("--kubeconfig").arg(kubeconfig);
    }
    if let Some(context) = context {
        command.arg("--kube-context").arg(context);
    }
    command.stdin(Stdio::null()).kill_on_drop(true);
    command
}

pub async fn kubectl(args: &[&str]) -> String {
    let output = tokio::time::timeout(
        Duration::from_mins(2),
        kubectl_command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("kubectl {args:?} did not finish within two minutes"))
    .unwrap_or_else(|error| panic!("spawn kubectl {args:?}: {error}"));
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

pub async fn kubectl_json(args: &[&str]) -> serde_json::Value {
    serde_json::from_str(&kubectl(args).await).expect("parse kubectl JSON")
}

/// The Sandbox resource of an `OpenShell` sandbox.
async fn sandbox_resource(name: &str) -> serde_json::Value {
    let list = kubectl_json(&[
        "get",
        "sandboxes.agents.x-k8s.io",
        "--all-namespaces",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
        "-o",
        "json",
    ])
    .await;
    let [resource] = list["items"].as_array().expect("Sandbox items").as_slice() else {
        panic!("expected one Sandbox resource for {name}: {list}");
    };
    resource.clone()
}

/// Identity of a sandbox's running generation as Kubernetes records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    pub route: String,
    pub runtime: String,
    pub workload_pod_uid: String,
}

pub async fn generation(name: &str) -> Generation {
    let resource = sandbox_resource(name).await;
    let annotations = &resource["metadata"]["annotations"];
    let namespace = resource["metadata"]["namespace"]
        .as_str()
        .expect("Sandbox namespace");
    let resource_name = resource["metadata"]["name"].as_str().expect("Sandbox name");
    let resource_uid = resource["metadata"]["uid"].as_str().expect("Sandbox UID");
    let pods = kubectl_json(&[
        "-n",
        namespace,
        "get",
        "pods",
        "-l",
        "openshell.ai/boundary-role=workload",
        "-o",
        "json",
    ])
    .await;
    let workload = pods["items"]
        .as_array()
        .expect("Pod items")
        .iter()
        .find(|pod| {
            pod["metadata"]["name"] == resource_name
                || pod["metadata"]["ownerReferences"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|owner| owner["uid"] == resource_uid)
        })
        .unwrap_or_else(|| panic!("no workload Pod for {name}: {pods}"));
    Generation {
        route: annotations[INSTANCE_ROUTE_ANNOTATION]
            .as_str()
            .unwrap_or_else(|| panic!("{name} is not on the shared supervisor: {annotations}"))
            .to_string(),
        runtime: annotations[GENERATION_ANNOTATION]
            .as_str()
            .unwrap_or_else(|| panic!("{name} has no runtime generation: {annotations}"))
            .to_string(),
        workload_pod_uid: workload["metadata"]["uid"]
            .as_str()
            .expect("workload Pod UID")
            .to_string(),
    }
}

/// The release's shared supervisor Pods, as JSON.
pub async fn supervisor_pod_items() -> Vec<serde_json::Value> {
    let list = kubectl_json(&[
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
    list["items"].as_array().expect("Pod items").clone()
}

/// Names of the running shared supervisor Pods.
pub async fn supervisor_pods() -> Vec<String> {
    supervisor_pod_items()
        .await
        .iter()
        .filter(|pod| {
            pod["metadata"]["deletionTimestamp"].is_null() && pod["status"]["phase"] == "Running"
        })
        .map(|pod| {
            pod["metadata"]["name"]
                .as_str()
                .expect("Pod name")
                .to_string()
        })
        .collect()
}

/// Whether `text` holds `phrase` followed by exactly `value` as a whole
/// token: a route or member name that merely starts with `value` does not
/// count.
fn names(text: &str, phrase: &str, value: &str) -> bool {
    let needle = format!("{phrase}{value}");
    text.match_indices(&needle).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + needle.len()..].chars().next();
        let token = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.';
        (phrase.ends_with(' ') || before.is_none_or(|c| !token(c)))
            && after.is_none_or(|c| !token(c))
    })
}

/// What one supervisor log line says about who supervises `route`:
/// `Some(true)` for an admission, `Some(false)` for a removal or release,
/// and `None` for anything else, including lines that only mention the route
/// (such as an SSH relay's socket path).
pub fn ownership_event(line: &str, route: &str) -> Option<bool> {
    let line = strip_ansi(line);
    if names(&line, &format!("{ADMITTED} "), route) {
        Some(true)
    } else if RELEASES
        .iter()
        .any(|phrase| names(&line, &format!("{phrase} "), route))
    {
        Some(false)
    } else {
        None
    }
}

/// Whether a supervisor's log says it supervises `route` now: its latest
/// ownership event for the route is an admission.
pub fn supervises(logs: &str, route: &str) -> bool {
    logs.lines()
        .rev()
        .find_map(|line| ownership_event(line, route))
        .unwrap_or(false)
}

/// Whether a gateway log line records moving `route` from member `from`
/// for `cause`, with the gateway's styling removed.
pub fn is_takeover(line: &str, route: &str, from: &str, cause: &str) -> bool {
    let line = strip_ansi(line);
    line.contains(TAKEOVER)
        && names(&line, "route=", route)
        && names(&line, "from=", from)
        && names(&line, "cause=", cause)
}

/// The supervisor Pod that currently supervises `route`, judged from what
/// each running member logged about it last.
pub async fn owner_of(route: &str) -> Option<String> {
    for pod in supervisor_pods().await {
        let Ok(Ok(logs)) = tokio::time::timeout(
            Duration::from_secs(30),
            kubectl_command()
                .args([
                    "-n",
                    &release_namespace(),
                    "logs",
                    &pod,
                    "-c",
                    SUPERVISOR_CONTAINER,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output(),
        )
        .await
        else {
            continue;
        };
        if supervises(&String::from_utf8_lossy(&logs.stdout), route) {
            return Some(pod);
        }
    }
    None
}

/// The latest attach or detach line `pod`'s supervisor logged, if any.
async fn attachment(pod: &str) -> Option<String> {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        kubectl_command()
            .args([
                "-n",
                &release_namespace(),
                "logs",
                pod,
                "-c",
                SUPERVISOR_CONTAINER,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .rev()
        .find(|line| line.contains(ATTACHED) || line.contains(DETACHED))
        .map(str::to_string)
}

/// Wait until every one of `members` is attached to the gateway now (its
/// latest stream event is an acceptance, not a loss), and its membership
/// record has had time to be written. Pod readiness only means the process
/// listens; it says nothing about authenticating to the gateway.
pub async fn wait_until_attached(members: &[String]) {
    let mut last = std::collections::BTreeMap::new();
    let attached = tokio::time::timeout(ATTACH_TIMEOUT, async {
        loop {
            let mut all = true;
            for member in members {
                let event = attachment(member).await;
                all &= event.as_deref().is_some_and(|line| line.contains(ATTACHED));
                last.insert(member.clone(), event);
            }
            if all {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    assert!(
        attached.is_ok(),
        "supervisor pool members did not attach to the gateway within {ATTACH_TIMEOUT:?}; latest stream event per member: {last:#?}"
    );
    tokio::time::sleep(MEMBERSHIP_RECORD_BOUND).await;
}

pub async fn wait_for_owner(route: &str) -> String {
    tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            if let Some(owner) = owner_of(route).await {
                return owner;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no shared supervisor admitted route {route}"))
}

/// PID, start time, and counter of a sandbox's main process.
#[derive(Debug, Clone)]
pub struct MainProcess {
    pub pid: u32,
    pub start_ticks: u64,
    pub counter: u64,
}

/// One bounded exec probe of the main process.
pub async fn main_process(sandbox: &SandboxGuard) -> Result<MainProcess, String> {
    let output = tokio::time::timeout(
        EXEC_PROBE_TIMEOUT,
        sandbox.exec(&[
            "sh",
            "-c",
            "pid=$(cat /tmp/ha-main.pid) && echo pid=$pid && \
             echo start=$(cut -d')' -f2 /proc/$pid/stat | awk '{print $20}') && \
             echo counter=$(cat /tmp/ha-counter)",
        ]),
    )
    .await
    .map_err(|_| format!("exec did not finish within {EXEC_PROBE_TIMEOUT:?}"))??;
    let field = |key: &str| {
        output
            .lines()
            .find_map(|line| line.trim().strip_prefix(key))
            .and_then(|value| value.trim().parse::<u64>().ok())
            .ok_or_else(|| format!("no {key} in main process report:\n{output}"))
    };
    Ok(MainProcess {
        pid: u32::try_from(field("pid=")?).map_err(|error| error.to_string())?,
        start_ticks: field("start=")?,
        counter: field("counter=")?,
    })
}

/// Wait until the same main process as `previous` has counted past it. A
/// successful read alone does not prove a tick happened since the last one.
pub async fn counts_past(sandbox: &SandboxGuard, previous: &MainProcess) -> MainProcess {
    tokio::time::timeout(Duration::from_mins(1), async {
        loop {
            if let Ok(current) = main_process(sandbox).await {
                assert_eq!(current.pid, previous.pid, "the main process was restarted");
                assert_eq!(
                    current.start_ticks, previous.start_ticks,
                    "a new process reused the main process's PID"
                );
                if current.counter > previous.counter {
                    return current;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} stopped counting after {previous:?}", sandbox.name))
}

/// Host endpoint that answers every request with `HA_OK`.
pub struct HostEndpoint {
    pub port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl HostEndpoint {
    pub async fn start() -> Self {
        let listener = TcpListener::bind(("0.0.0.0", 0))
            .await
            .expect("bind host endpoint");
        let port = listener.local_addr().expect("endpoint address").port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = answer(stream).await;
                });
            }
        });
        Self { port, task }
    }
}

impl Drop for HostEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The host endpoint's only response.
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHA_OK";

/// Read one request head and answer it; returns the head as received.
async fn answer(stream: TcpStream) -> std::io::Result<String> {
    let mut reader = tokio::io::BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            break;
        }
        head.push_str(&line);
        if line == "\r\n" {
            break;
        }
    }
    reader.get_mut().write_all(RESPONSE).await?;
    Ok(head)
}

pub fn policy(port: u16) -> tempfile::NamedTempFile {
    let mut file = tempfile::Builder::new()
        .suffix(".yaml")
        .tempfile()
        .expect("create policy file");
    std::io::Write::write_all(
        &mut file,
        format!(
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
  ha:
    name: ha
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
        )
        .as_bytes(),
    )
    .expect("write policy file");
    file
}

/// Python that sends one HTTP request to `host:port` and prints `HA_OK`,
/// `UNEXPECTED`, or `DENIED`. The policy enforces the request's authority, so
/// the Host header names the port as well as the host. The Rust raw string
/// leaves `\r\n` for Python's bytes literal to turn into CRLF.
fn host_call_script(host: &str, port: u16) -> String {
    format!(
        r#"
import socket
try:
    with socket.create_connection(({host:?}, {port}), timeout=15) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n")
        sock.settimeout(15)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
    print("HA_OK" if b"HA_OK" in response else "UNEXPECTED")
except OSError:
    print("DENIED")
"#
    )
}

/// One bounded call from the sandbox to the host endpoint through its policy:
/// `HA_OK`, `UNEXPECTED`, `DENIED`, or `NO_RESULT`.
pub async fn try_call_host(sandbox: &SandboxGuard, port: u16) -> Result<String, String> {
    let script = host_call_script(TEST_HOST, port);
    let output = tokio::time::timeout(
        NETWORK_PROBE_TIMEOUT,
        sandbox.exec(&["python3", "-c", &script]),
    )
    .await
    .map_err(|_| format!("network probe did not finish within {NETWORK_PROBE_TIMEOUT:?}"))??;
    Ok(output
        .lines()
        .map(str::trim)
        .find(|line| matches!(*line, "HA_OK" | "UNEXPECTED" | "DENIED"))
        .unwrap_or("NO_RESULT")
        .to_string())
}

/// Call the host endpoint from the sandbox through its policy.
pub async fn call_host(sandbox: &SandboxGuard, port: u16) -> String {
    try_call_host(sandbox, port)
        .await
        .unwrap_or_else(|error| panic!("call host from {}: {error}", sandbox.name))
}

/// Gateway log lines that mention `route`, from every gateway Pod, without
/// the styling the gateway's console format puts between field names, `=`,
/// and values.
pub async fn gateway_log_lines(route: &str) -> Vec<String> {
    let namespace = release_namespace();
    let pods = kubectl_json(&[
        "-n",
        &namespace,
        "get",
        "pods",
        "-l",
        GATEWAY_SELECTOR,
        "-o",
        "json",
    ])
    .await;
    let pods = pods["items"]
        .as_array()
        .expect("Pod items")
        .iter()
        .map(|pod| {
            pod["metadata"]["name"]
                .as_str()
                .expect("Pod name")
                .to_string()
        })
        .collect::<Vec<_>>();
    assert!(!pods.is_empty(), "no gateway Pods match {GATEWAY_SELECTOR}");
    let mut lines = Vec::new();
    for pod in pods {
        let logs = kubectl(&["-n", &namespace, "logs", &pod, "-c", GATEWAY_CONTAINER]).await;
        lines.extend(
            logs.lines()
                .map(strip_ansi)
                .filter(|line| line.contains(route)),
        );
    }
    lines
}

/// Create a sandbox whose main process counts in memory, and wait until it
/// counts.
pub async fn create(policy: &tempfile::NamedTempFile) -> SandboxGuard {
    let policy = policy.path().to_str().expect("UTF-8 policy path");
    let sandbox = SandboxGuard::create_detached_main_with_args(
        &["--policy", policy],
        &["sh", "-c", COUNTER_MAIN],
    )
    .await
    .expect("create sandbox");
    tokio::time::timeout(Duration::from_mins(2), async {
        while main_process(&sandbox).await.is_err() {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} never started counting", sandbox.name));
    sandbox
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE: &str = "rt-17999333d7754f3e957b9cf2fca0ee29";

    fn supervisor_line(message: &str) -> String {
        format!("2026-10-23T06:07:20.104Z INFO openshell_supervisor::shared_host: {message}")
    }

    #[test]
    fn an_admission_in_shorthand_output_names_its_owner() {
        let logs = [
            supervisor_line("gateway accepted the supervisor host"),
            supervisor_line(&format!("{ADMITTED} {ROUTE}")),
        ]
        .join("\n");
        assert!(supervises(&logs, ROUTE));
    }

    #[test]
    fn lines_that_only_mention_the_route_change_nothing() {
        // SSH relay activity after the admission names the route only in a
        // socket path.
        let logs = [
            supervisor_line(&format!("{ADMITTED} {ROUTE}")),
            supervisor_line(&format!(
                "SSH relay opened socket=/run/openshell/sessions/{ROUTE}/ssh.sock"
            )),
            supervisor_line(&format!(
                "SSH relay closed /run/openshell/sessions/{ROUTE}/ssh.sock"
            )),
        ]
        .join("\n");
        assert!(supervises(&logs, ROUTE));
        assert_eq!(ownership_event(logs.lines().last().unwrap(), ROUTE), None);
    }

    #[test]
    fn a_removal_or_release_ends_supervision() {
        for release in RELEASES.iter().take(2) {
            let logs = [
                supervisor_line(&format!("{ADMITTED} {ROUTE}")),
                supervisor_line(&format!("{release} {ROUTE}")),
                supervisor_line(&format!(
                    "SSH relay closed /run/openshell/sessions/{ROUTE}/ssh.sock"
                )),
            ]
            .join("\n");
            assert!(!supervises(&logs, ROUTE), "{release}");
        }
    }

    #[test]
    fn adopting_a_later_term_keeps_supervising() {
        let logs = [
            supervisor_line(&format!("{ADMITTED} {ROUTE}")),
            supervisor_line(&format!("{} {ROUTE}", RELEASES[2])),
            supervisor_line(&format!("{ADMITTED} {ROUTE}")),
        ]
        .join("\n");
        assert!(supervises(&logs, ROUTE));
    }

    #[test]
    fn another_route_sharing_a_prefix_is_not_this_route() {
        let logs = supervisor_line(&format!("{ADMITTED} {ROUTE}0"));
        assert!(!supervises(&logs, ROUTE));
        assert!(!supervises("", ROUTE));
    }

    /// A takeover line as the gateway's styled console prints it: italic
    /// field names, a dimmed `=`, plain values.
    fn styled_takeover(route: &str, from: &str, to: &str, cause: &str) -> String {
        let field = |key: &str, value: &str| format!("\x1b[3m{key}\x1b[0m\x1b[2m=\x1b[0m{value}");
        format!(
            "\x1b[2m2026-10-23T06:09:01.512Z\x1b[0m \x1b[32m INFO\x1b[0m \x1b[2mopenshell_server::supervisor_pool\x1b[0m\x1b[2m:\x1b[0m {TAKEOVER} {} {} {} {} {} {}",
            field("sandbox_id", "sandbox-1"),
            field("route", route),
            field("from", from),
            field("to", to),
            field("term", "2"),
            field("cause", cause),
        )
    }

    /// The sandbox's request reaches a listener as a well-formed HTTP request
    /// whose authority names the port, and the endpoint's answer reads as
    /// `HA_OK`: the exact bytes both ways, without a cluster.
    #[tokio::test]
    async fn the_host_call_sends_a_request_with_its_authority_and_reads_the_answer() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            answer(stream).await.unwrap()
        });
        let output = match tokio::process::Command::new("python3")
            .args(["-c", &host_call_script("127.0.0.1", port)])
            .stdin(Stdio::null())
            .output()
            .await
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("python3 is not installed; skipping");
                return;
            }
            Err(error) => panic!("run python3: {error}"),
        };
        let head = tokio::time::timeout(Duration::from_secs(20), served)
            .await
            .expect("the request arrives")
            .unwrap();
        assert_eq!(
            head,
            format!("GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "HA_OK",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // The response's Content-Length is its body's.
        let (headers, body) = std::str::from_utf8(RESPONSE)
            .unwrap()
            .split_once("\r\n\r\n")
            .unwrap();
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
    }

    #[test]
    fn a_styled_takeover_line_matches_its_route_member_and_cause() {
        let line = styled_takeover(
            ROUTE,
            "openshell-supervisor-abc-1",
            "openshell-supervisor-abc-2",
            "leaving",
        );
        assert!(!line.contains("cause=leaving"), "the fixture is styled");
        assert!(is_takeover(
            &line,
            ROUTE,
            "openshell-supervisor-abc-1",
            "leaving"
        ));
        assert!(!is_takeover(
            &line,
            ROUTE,
            "openshell-supervisor-abc-1",
            "expired"
        ));
        assert!(!is_takeover(
            &line,
            ROUTE,
            "openshell-supervisor-abc-2",
            "leaving"
        ));
        assert!(!is_takeover(
            &line,
            ROUTE,
            "openshell-supervisor-abc",
            "leaving"
        ));
        assert!(!is_takeover(
            &line,
            "rt-other",
            "openshell-supervisor-abc-1",
            "leaving"
        ));
    }
}
