// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor-ha")]

//! A high-availability pool of shared supervisors (`supervisor_topology =
//! "gateway"` with two or more replicas).
//!
//! Killing the supervisor Pod that owns a sandbox instance, abruptly so it
//! cannot announce that it is leaving, moves the instance to another pool
//! member once its membership expires, and that member adopts the running
//! workload. The workload Pod, runtime generation, main process, and the
//! process's in-memory state survive; exec and policy-mediated networking work
//! again; and a sandbox on another member keeps running and answering
//! throughout, under the same owner.

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
/// Sandboxes created, at most, until two land on different members.
const PLACEMENT_ATTEMPTS: usize = 8;
/// A member that announces it is leaving is drained within a reconciliation
/// pass (2 s); an abruptly lost member is taken over only once its record
/// expires (15 s TTL, refreshed every 2 s). A move this late cannot come from
/// a leave.
const EXPIRY_EVIDENCE: Duration = Duration::from_secs(10);
/// Gateway Pods of the release: the chart's selector labels name the gateway
/// `openshell`, while the supervisor and certgen Pods carry their own names.
const GATEWAY_SELECTOR: &str = "app.kubernetes.io/name=openshell";
const GATEWAY_CONTAINER: &str = "openshell-gateway";
const SUPERVISOR_CONTAINER: &str = "supervisor";
/// What a supervisor logs as it begins to leave the pool.
const LEAVING: &str = "pool member is leaving";
const TAKEOVER: &str = "taking over a shared sandbox instance from a failed supervisor";
/// Takeover cause the gateway logs when the owner's membership record expired.
const EXPIRED_CAUSE: &str = "cause=expired";

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

/// Run `command` in a cluster node's container; k3d and kind name node
/// containers after their nodes.
async fn node_exec(node: &str, command: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new("docker")
        .arg("exec")
        .arg(node)
        .args(command)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| format!("docker exec {node} {command:?}: {error}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "docker exec {node} {command:?}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// SIGKILL the supervisor container of `pod` through its node's container
/// runtime, so it cannot announce that it is leaving, then force-delete the
/// Pod so its member does not come back in place. Kills the task with
/// `ctr`, or failing that the container's process with `kill -KILL`; panics
/// when neither succeeds. Returns how the container was killed.
async fn kill_abruptly(pod: &str) -> String {
    let namespace = release_namespace();
    let description = kubectl_json(&["-n", &namespace, "get", "pod", pod, "-o", "json"]).await;
    let node = description["spec"]["nodeName"]
        .as_str()
        .unwrap_or_else(|| panic!("{pod} has no node: {description}"))
        .to_string();
    let container = description["status"]["containerStatuses"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|status| status["name"] == SUPERVISOR_CONTAINER)
        .and_then(|status| status["containerID"].as_str())
        .and_then(|id| id.split_once("://").map(|(_, id)| id.to_string()))
        .unwrap_or_else(|| panic!("{pod} has no running {SUPERVISOR_CONTAINER} container"));
    let mut failures = Vec::new();
    let mut killed = None;
    // k3s ships `ctr` as a multi-call alias; kind ships it on its own.
    for ctr in [&["ctr"][..], &["k3s", "ctr"][..]] {
        let kill = [
            ctr,
            &[
                "-n", "k8s.io", "tasks", "kill", "--signal", "SIGKILL", &container,
            ],
        ]
        .concat();
        match node_exec(&node, &kill).await {
            Ok(_) => {
                killed = Some(format!("ctr tasks kill --signal SIGKILL on {node}"));
                break;
            }
            Err(error) => failures.push(error),
        }
    }
    if killed.is_none() {
        for ctr in [&["ctr"][..], &["k3s", "ctr"][..]] {
            let list = [ctr, &["-n", "k8s.io", "tasks", "ls"]].concat();
            let pid = match node_exec(&node, &list).await {
                Ok(tasks) => tasks.lines().find_map(|line| {
                    let mut fields = line.split_whitespace();
                    (fields.next() == Some(container.as_str()))
                        .then(|| fields.next())
                        .flatten()
                        .filter(|pid| pid.parse::<u32>().is_ok_and(|pid| pid > 1))
                        .map(str::to_string)
                }),
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            let Some(pid) = pid else {
                failures.push(format!("no running task {container} on {node}"));
                continue;
            };
            match node_exec(&node, &["kill", "-KILL", &pid]).await {
                Ok(_) => {
                    killed = Some(format!("kill -KILL {pid} on {node}"));
                    break;
                }
                Err(error) => failures.push(error),
            }
        }
    }
    let killed = killed.unwrap_or_else(|| {
        panic!(
            "could not hard-kill supervisor {pod}; a graceful stop proves nothing: {failures:#?}"
        )
    });
    kubectl(&[
        "-n",
        &namespace,
        "delete",
        "pod",
        pod,
        "--grace-period=0",
        "--force",
        "--wait=false",
    ])
    .await;
    killed
}

/// Lines a supervisor Pod logs from its start until its container ends.
struct FollowedLogs {
    lines: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ended: tokio::sync::oneshot::Receiver<()>,
    _child: tokio::process::Child,
}

impl FollowedLogs {
    /// Follow `pod`'s supervisor log, once it shows the admission of `route`.
    async fn start(pod: &str, route: &str) -> Self {
        let mut child = kubectl_command()
            .args([
                "-n",
                &release_namespace(),
                "logs",
                "--follow",
                pod,
                "-c",
                SUPERVISOR_CONTAINER,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn kubectl logs --follow");
        let stdout = child.stdout.take().expect("piped logs");
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (end, ended) = tokio::sync::oneshot::channel();
        let collected = lines.clone();
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                collected.lock().unwrap().push(line);
            }
            let _ = end.send(());
        });
        let logs = Self {
            lines,
            ended,
            _child: child,
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            while !logs.any(|line| line.contains(route)) {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{pod}'s followed log never showed {route}"));
        logs
    }

    fn any(&self, matches: impl Fn(&str) -> bool) -> bool {
        self.lines.lock().unwrap().iter().any(|line| matches(line))
    }

    /// Everything logged, once the container ended.
    async fn ended(mut self, pod: &str) -> Vec<String> {
        tokio::time::timeout(Duration::from_secs(30), &mut self.ended)
            .await
            .unwrap_or_else(|_| panic!("{pod}'s log did not end after the kill"))
            .ok();
        self.lines.lock().unwrap().clone()
    }
}

/// Gateway log lines that mention `route`, from every gateway Pod.
async fn gateway_log_lines(route: &str) -> Vec<String> {
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
                .filter(|line| line.contains(route))
                .map(str::to_string),
        );
    }
    lines
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

    // Two sandboxes on different members: create until the pool spreads one
    // away from the first, and remove the extra ones.
    let mut first = create(&policy).await;
    let first_generation = generation(&first.name).await;
    let first_owner = wait_for_owner(&first_generation.route).await;
    let mut extras = Vec::new();
    let mut placed = None;
    for _ in 0..PLACEMENT_ATTEMPTS {
        let candidate = create(&policy).await;
        let candidate_generation = generation(&candidate.name).await;
        let candidate_owner = wait_for_owner(&candidate_generation.route).await;
        if candidate_owner == first_owner {
            extras.push(candidate);
        } else {
            placed = Some((candidate, candidate_generation, candidate_owner));
            break;
        }
    }
    for mut extra in extras {
        extra.cleanup().await;
    }
    let (mut second, second_generation, second_owner) = placed.unwrap_or_else(|| {
        panic!(
            "the pool placed {} sandboxes on {first_owner} alone; members: {members:?}",
            PLACEMENT_ATTEMPTS + 1
        )
    });
    eprintln!(
        "{} on {first_owner}, {} on {second_owner}",
        first.name, second.name
    );
    assert_eq!(call_host(&first, endpoint.port).await, "HA_OK");
    let before = main_process(&first).await.expect("main process before");
    let second_before = main_process(&second)
        .await
        .expect("second main process before");

    // The owner is lost abruptly: its supervisor is killed without a chance
    // to announce that it is leaving or to hand anything over.
    let victim_logs = FollowedLogs::start(&first_owner, &first_generation.route).await;
    let killed_at = tokio::time::Instant::now();
    let killed = kill_abruptly(&first_owner).await;
    eprintln!("supervisor {first_owner} killed: {killed}");

    // The sandbox on the surviving member keeps answering, and counting,
    // while the other is recovered.
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

    // The route moves only once the lost member's record expires, which a
    // leaving member would not wait for.
    let moved_after = tokio::time::timeout(RECOVERY_DEADLINE, async {
        loop {
            if owner_of(&first_generation.route)
                .await
                .is_some_and(|owner| owner != first_owner)
            {
                return killed_at.elapsed();
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "no other member admitted {} within {RECOVERY_DEADLINE:?}",
            first.name
        )
    });
    // The cause is the member's failure, not a leave: the lost supervisor
    // logged nothing about leaving before it died, a gateway took the route
    // over from it, and the move waited for its record to expire.
    let victim_lines = victim_logs.ended(&first_owner).await;
    let left = victim_lines
        .iter()
        .filter(|line| line.contains(LEAVING))
        .collect::<Vec<_>>();
    assert!(
        left.is_empty(),
        "{first_owner} announced that it was leaving, so the kill ({killed}) was not abrupt: {left:?}"
    );
    // The gateway names the cause it saw: the member had no live record,
    // not a leaving flag or a restarted process.
    let takeover = gateway_log_lines(&first_generation.route).await;
    assert!(
        takeover.iter().any(|line| line.contains(TAKEOVER)
            && line.contains(&first_owner)
            && line.contains(EXPIRED_CAUSE)),
        "no gateway took {} over from {first_owner} because its record expired: {takeover:?}",
        first_generation.route
    );
    assert!(
        moved_after >= EXPIRY_EVIDENCE,
        "{} moved {moved_after:?} after the kill, sooner than its member's record could expire",
        first.name
    );

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

    // The other sandbox is still its original process, under its original
    // owner.
    assert_eq!(generation(&second.name).await, second_generation);
    assert_eq!(
        wait_for_owner(&second_generation.route).await,
        second_owner,
        "the surviving member's sandbox must not move"
    );
    assert_eq!(call_host(&second, endpoint.port).await, "HA_OK");
    let second_after = counts_past(&second, &second_before).await;
    assert_eq!(second_after.start_ticks, second_before.start_ticks);

    first.cleanup().await;
    second.cleanup().await;
}
