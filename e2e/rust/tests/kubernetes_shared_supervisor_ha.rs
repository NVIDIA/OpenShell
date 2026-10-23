// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor-ha")]

//! A high-availability pool of shared supervisors (`supervisor_topology =
//! "gateway"` with two or more replicas).
//!
//! Killing the supervisor Pod that owns a sandbox instance moves the instance
//! to another pool member, which adopts the running workload. The workload
//! Pod, runtime generation, main process, and the process's in-memory state
//! survive; exec and policy-mediated networking work again; and a sandbox
//! whose supervisor did not fail keeps running and answering throughout.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::sandbox::SandboxGuard;
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

const TEST_HOST: &str = "host.openshell.internal";
const SUPERVISOR_COMPONENT: &str = "app.kubernetes.io/component=supervisor";
const INSTANCE_ROUTE_ANNOTATION: &str = "openshell.ai/sandbox-runtime-supervisor-session";
const GENERATION_ANNOTATION: &str = "openshell.ai/sandbox-runtime-generation";
/// The workload's main process: it records its PID once and a counter that
/// lives only in its memory every second. A restarted process would start
/// counting from one again.
const COUNTER_MAIN: &str = "echo $$ > /tmp/ha-main.pid; i=0; while true; do i=$((i+1)); echo $i > /tmp/ha-counter; sleep 1; done";
/// Bound on the takeover: membership expiry, a reconciliation pass, the
/// replacement's startup, and the CLI's own retries.
const RECOVERY_DEADLINE: Duration = Duration::from_mins(3);

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

async fn kubectl_json(args: &[&str]) -> serde_json::Value {
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
#[derive(Debug, PartialEq, Eq)]
struct Generation {
    route: String,
    runtime: String,
    workload_pod_uid: String,
}

async fn generation(name: &str) -> Generation {
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

/// Names of the running shared supervisor Pods.
async fn supervisor_pods() -> Vec<String> {
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
    list["items"]
        .as_array()
        .expect("Pod items")
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

/// The supervisor Pod that currently supervises `route`, judged from what
/// each member logged about it last.
async fn owner_of(route: &str) -> Option<String> {
    for pod in supervisor_pods().await {
        let logs = kubectl_command()
            .args(["-n", &release_namespace(), "logs", &pod])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .await
            .expect("spawn kubectl logs");
        let logs = String::from_utf8_lossy(&logs.stdout);
        let last = logs.lines().rev().find(|line| line.contains(route));
        if last.is_some_and(|line| {
            line.contains("admitted assigned sandbox instance")
                && !line.contains("relinquish")
                && !line.contains("removing")
        }) {
            return Some(pod);
        }
    }
    None
}

async fn wait_for_owner(route: &str) -> String {
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
#[derive(Debug)]
struct MainProcess {
    pid: u32,
    start_ticks: u64,
    counter: u64,
}

async fn main_process(sandbox: &SandboxGuard) -> Result<MainProcess, String> {
    let output = sandbox
        .exec(&[
            "sh",
            "-c",
            "pid=$(cat /tmp/ha-main.pid) && echo pid=$pid && \
             echo start=$(cut -d')' -f2 /proc/$pid/stat | awk '{print $20}') && \
             echo counter=$(cat /tmp/ha-counter)",
        ])
        .await?;
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
async fn counts_past(sandbox: &SandboxGuard, previous: &MainProcess) -> MainProcess {
    tokio::time::timeout(Duration::from_secs(30), async {
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
struct HostEndpoint {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl HostEndpoint {
    async fn start() -> Self {
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

async fn answer(stream: TcpStream) -> std::io::Result<()> {
    let mut reader = tokio::io::BufReader::new(stream);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 || line == "\r\n" {
            break;
        }
    }
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHA_OK")
        .await
}

fn policy(port: u16) -> tempfile::NamedTempFile {
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

/// Call the host endpoint from the sandbox through its policy.
async fn call_host(sandbox: &SandboxGuard, port: u16) -> String {
    let script = format!(
        r#"
import socket
try:
    with socket.create_connection(({TEST_HOST:?}, {port}), timeout=15) as sock:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: {TEST_HOST}\r\nConnection: close\r\n\r\n")
        sock.settimeout(15)
        response = b""
        while chunk := sock.recv(4096):
            response += chunk
    print("HA_OK" if b"HA_OK" in response else "UNEXPECTED")
except OSError:
    print("DENIED")
"#
    );
    sandbox
        .exec(&["python3", "-c", &script])
        .await
        .unwrap_or_else(|error| panic!("call host from {}: {error}", sandbox.name))
        .lines()
        .map(str::trim)
        .find(|line| matches!(*line, "HA_OK" | "UNEXPECTED" | "DENIED"))
        .unwrap_or("NO_RESULT")
        .to_string()
}

async fn create(policy: &tempfile::NamedTempFile) -> SandboxGuard {
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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn losing_a_supervisor_pod_moves_its_sandboxes_without_restarting_them() {
    let members = supervisor_pods().await;
    assert!(
        members.len() >= 2,
        "the supervisor pool needs at least two running members: {members:?}"
    );
    let endpoint = HostEndpoint::start().await;
    let policy = policy(endpoint.port);
    let (first, second) = tokio::join!(create(&policy), create(&policy));
    let (mut first, mut second) = (first, second);

    let first_generation = generation(&first.name).await;
    let second_generation = generation(&second.name).await;
    let first_owner = wait_for_owner(&first_generation.route).await;
    let second_owner = wait_for_owner(&second_generation.route).await;
    eprintln!(
        "{} on {first_owner}, {} on {second_owner}",
        first.name, second.name
    );
    assert_eq!(call_host(&first, endpoint.port).await, "HA_OK");
    let before = main_process(&first).await.expect("main process before");
    let second_before = main_process(&second)
        .await
        .expect("second main process before");

    // The owner's Pod is lost: its supervisor is killed without a chance to
    // hand anything over.
    kubectl(&[
        "-n",
        &release_namespace(),
        "delete",
        "pod",
        &first_owner,
        "--grace-period=0",
        "--force",
        "--wait=false",
    ])
    .await;

    // A sandbox whose supervisor survived keeps answering while the other
    // is recovered.
    if second_owner != first_owner {
        let during = main_process(&second)
            .await
            .expect("a sandbox of the surviving member answers during the failover");
        tokio::time::sleep(Duration::from_secs(3)).await;
        let later = main_process(&second).await.expect("still answering");
        assert_eq!(during.pid, later.pid);
        assert!(
            later.counter > during.counter,
            "the surviving member's workload must keep running: {during:?} then {later:?}"
        );
    }

    // The lost owner's sandbox comes back through its new owner.
    let after = tokio::time::timeout(RECOVERY_DEADLINE, async {
        loop {
            if let Ok(after) = main_process(&first).await {
                return after;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{} was not recovered within {RECOVERY_DEADLINE:?}",
            first.name
        )
    });

    // Same Pod, same generation, same process: the workload was adopted, not
    // restarted, and keeps counting on from the state that lives only in its
    // memory.
    assert_eq!(generation(&first.name).await, first_generation);
    assert_eq!(after.pid, before.pid, "the main process was restarted");
    assert_eq!(
        after.start_ticks, before.start_ticks,
        "a new process reused the main process's PID"
    );
    let after = counts_past(&first, &before).await;
    let new_owner = wait_for_owner(&first_generation.route).await;
    assert_ne!(new_owner, first_owner, "the lost Pod cannot own the route");

    // Mediated networking works again through the replacement's policy, and
    // the workload is running again.
    assert_eq!(call_host(&first, endpoint.port).await, "HA_OK");
    counts_past(&first, &after).await;

    // The other sandbox is still its original process too.
    assert_eq!(generation(&second.name).await, second_generation);
    assert_eq!(call_host(&second, endpoint.port).await, "HA_OK");
    counts_past(&second, &second_before).await;

    first.cleanup().await;
    second.cleanup().await;
}
