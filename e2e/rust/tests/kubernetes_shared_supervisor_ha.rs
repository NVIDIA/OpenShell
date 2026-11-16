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
//!
//! The pool sits behind two gateway replicas sharing a database. Every pool
//! sandbox's session runs on the replica serving its supervisor at start and
//! after a gateway crash, a gateway rolling restart, and a supervisor crash;
//! exec reaches every sandbox after each step.

mod shared_supervisor;

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::sandbox::SandboxGuard;
use shared_supervisor::{
    EXEC_PROBE_TIMEOUT, GATEWAY_SELECTOR, HostEndpoint, SUPERVISOR_CONTAINER, call_host,
    counts_past, create, gateway_log_lines, generation, is_takeover, kubectl, kubectl_command,
    kubectl_json, main_process, owner_of, policy, release_namespace, supervisor_pods,
    wait_for_owner, wait_until_attached,
};
use tokio::io::AsyncBufReadExt as _;

/// Bound on the takeover: membership expiry, a reconciliation pass, the
/// replacement's startup, and the CLI's own retries.
const RECOVERY_DEADLINE: Duration = Duration::from_mins(3);
/// Sandboxes created, at most, until two land on different members. The ring
/// places each sandbox by its random server-assigned ID, so placements can
/// cluster on one member for many sandboxes in a row; the bound must not
/// assume they alternate (eight in a row on one member was seen live).
const PLACEMENT_ATTEMPTS: usize = 32;
/// A member that announces it is leaving is drained within a reconciliation
/// pass (2 s); an abruptly lost member is taken over only once its record
/// expires (15 s TTL, refreshed every 2 s). A move this late cannot come from
/// a leave.
const EXPIRY_EVIDENCE: Duration = Duration::from_secs(10);
/// What a supervisor logs as it begins to leave the pool.
const LEAVING: &str = "pool member is leaving";

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

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn losing_a_supervisor_pod_moves_its_sandboxes_without_restarting_them() {
    let members = supervisor_pods().await;
    assert!(
        members.len() >= 2,
        "the supervisor pool needs at least two running members: {members:?}"
    );
    wait_until_attached(&members).await;
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
        takeover.iter().any(|line| is_takeover(
            line,
            &first_generation.route,
            &first_owner,
            "expired"
        )),
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

const SANDBOXES: usize = 4;
const SETTLE_DEADLINE: Duration = Duration::from_mins(3);
const POSTGRES: &str = "deploy/openshell-e2e-postgres";
/// Each granted pool sandbox's route with its owning member, the replica
/// serving that member's stream, and the replica owning the sandbox's session.
const TREE: &str = "\
WITH io AS (SELECT convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_instance_owner'),
     pm AS (SELECT convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_pool_member'),
     so AS (SELECT substring(id FROM 'supervisor-owner:(.*)') AS sandbox_id,
                   convert_from(payload, 'UTF8')::json AS p FROM objects
            WHERE object_type = 'supervisor_session_owner')
SELECT io.p->>'route', io.p->>'member_id', coalesce(pm.p->>'gateway_replica', ''),
       coalesce(so.p->>'owner_replica_id', '')
FROM io LEFT JOIN pm ON pm.p->>'member_id' = io.p->>'member_id'
LEFT JOIN so ON so.sandbox_id = io.p->>'sandbox_id'
WHERE io.p->>'phase' = 'granted'";

#[derive(Debug)]
struct Branch {
    member: String,
    supervisor_gateway: String,
    session_gateway: String,
}

async fn tree(routes: &[String]) -> Vec<Branch> {
    kubectl(&[
        "-n",
        &release_namespace(),
        "exec",
        POSTGRES,
        "--",
        "psql",
        "-U",
        "openshell",
        "-d",
        "openshell",
        "-XAt",
        "-F",
        "|",
        "-c",
        TREE,
    ])
    .await
    .lines()
    .filter_map(|row| {
        let mut fields = row.split('|');
        let route = fields.next()?;
        if !routes.iter().any(|ours| ours == route) {
            return None;
        }
        Some(Branch {
            member: fields.next()?.to_string(),
            supervisor_gateway: fields.next()?.to_string(),
            session_gateway: fields.next()?.to_string(),
        })
    })
    .collect()
}

/// Wait until the session of every sandbox on `routes` runs on its
/// supervisor's replica and no record names a `gone` gateway or supervisor Pod.
async fn assert_tree(step: &str, routes: &[String], gone: &[String]) -> Vec<Branch> {
    let mut last = Vec::new();
    let settled = tokio::time::timeout(SETTLE_DEADLINE, async {
        loop {
            last = tree(routes).await;
            if last.len() == routes.len()
                && last.iter().all(|branch| {
                    !branch.session_gateway.is_empty()
                        && branch.session_gateway == branch.supervisor_gateway
                        && !gone.contains(&branch.member)
                        && !gone.contains(&branch.session_gateway)
                })
            {
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    assert!(
        !last.is_empty(),
        "{step}: no pool records for {routes:?}; TREE may not match the gateway's `objects` schema"
    );
    assert!(
        settled.is_ok(),
        "{step}: sessions did not settle on their supervisor's gateway within {SETTLE_DEADLINE:?}: {last:#?}"
    );
    last
}

/// Reopens the CLI's port-forward when the gateway Pod behind it is gone. The
/// new port-forward outlives the test, so later tests keep the CLI's address.
struct GatewayForward {
    port: u16,
    child: Option<tokio::process::Child>,
}

impl GatewayForward {
    fn new() -> Self {
        let config = std::env::var("XDG_CONFIG_HOME").expect("XDG_CONFIG_HOME");
        let gateway = std::env::var("OPENSHELL_GATEWAY").expect("OPENSHELL_GATEWAY");
        let metadata: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{config}/openshell/gateways/{gateway}/metadata.json"
            ))
            .expect("read gateway metadata"),
        )
        .expect("parse gateway metadata");
        let port = metadata["gateway_port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .expect("gateway_port");
        Self { port, child: None }
    }

    #[allow(
        clippy::disallowed_methods,
        reason = "the e2e workspace does not depend on openshell-core"
    )]
    async fn reachable(&self) -> bool {
        tokio::net::TcpStream::connect(("127.0.0.1", self.port))
            .await
            .is_ok()
    }

    /// Returns once the port answers through a live port-forward: the
    /// harness's, or one this started that has not exited, for example after
    /// losing the port to a dying predecessor.
    async fn ensure(&mut self) {
        let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
        loop {
            let ours_alive = self
                .child
                .as_mut()
                .map(|child| matches!(child.try_wait(), Ok(None)));
            match (ours_alive, self.reachable().await) {
                (None | Some(true), true) => return,
                (Some(true), false) => {}
                _ => {
                    self.child = Some(
                        kubectl_command()
                            .args([
                                "-n",
                                &release_namespace(),
                                "port-forward",
                                &format!("svc/{}", release()),
                                &format!("{}:8080", self.port),
                            ])
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .kill_on_drop(false)
                            .spawn()
                            .expect("spawn kubectl port-forward"),
                    );
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no live port-forward on {}",
                self.port
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

async fn assert_exec(step: &str, forward: &mut GatewayForward, sandboxes: &[SandboxGuard]) {
    for sandbox in sandboxes {
        let mut last = String::new();
        let reached = tokio::time::timeout(SETTLE_DEADLINE, async {
            loop {
                forward.ensure().await;
                match tokio::time::timeout(EXEC_PROBE_TIMEOUT, sandbox.exec(&["true"])).await {
                    Ok(Ok(_)) => return,
                    Ok(Err(error)) => last = error,
                    Err(_) => last = "exec timed out".to_string(),
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
        .await;
        assert!(
            reached.is_ok(),
            "{step}: exec into {} failed: {last}",
            sandbox.name
        );
    }
}

fn release() -> String {
    std::env::var("OPENSHELL_E2E_KUBE_RELEASE").expect("OPENSHELL_E2E_KUBE_RELEASE")
}

async fn gateway_pods() -> Vec<String> {
    kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "pods",
        "-l",
        GATEWAY_SELECTOR,
        "-o",
        "jsonpath={.items[*].metadata.name}",
    ])
    .await
    .split_whitespace()
    .map(str::to_string)
    .collect()
}

/// The gateway's workload, a Deployment or a `StatefulSet`.
async fn gateway_workload() -> String {
    kubectl(&[
        "-n",
        &release_namespace(),
        "get",
        "deploy,statefulset",
        "--field-selector",
        &format!("metadata.name={}", release()),
        "-o",
        "name",
    ])
    .await
    .trim()
    .to_string()
}

async fn rollout(action: &str, workload: &str) {
    kubectl(&[
        "-n",
        &release_namespace(),
        "rollout",
        action,
        workload,
        "--timeout=300s",
    ])
    .await;
}

async fn force_delete(pod: &str) {
    kubectl(&[
        "-n",
        &release_namespace(),
        "delete",
        "pod",
        pod,
        "--grace-period=0",
        "--force",
    ])
    .await;
}

#[tokio::test]
async fn pool_sessions_follow_their_supervisors_gateway() {
    let gateway = gateway_workload().await;
    let supervisor = format!("deployment.apps/{}-supervisor", release());
    assert_eq!(
        gateway_pods().await.len(),
        2,
        "the lane runs two gateway replicas"
    );
    wait_until_attached(&supervisor_pods().await).await;

    let mut forward = GatewayForward::new();
    forward.ensure().await;
    let mut sandboxes = Vec::new();
    for _ in 0..SANDBOXES {
        sandboxes.push(
            SandboxGuard::create_detached_main_with_args(&[], &["sleep", "infinity"])
                .await
                .expect("create sandbox"),
        );
    }
    let mut routes = Vec::new();
    for sandbox in &sandboxes {
        routes.push(generation(&sandbox.name).await.route);
    }
    let branches = assert_tree("start", &routes, &[]).await;
    assert_exec("start", &mut forward, &sandboxes).await;

    let crashed = vec![branches[0].supervisor_gateway.clone()];
    force_delete(&crashed[0]).await;
    rollout("status", &gateway).await;
    assert_tree("gateway crash", &routes, &crashed).await;
    assert_exec("gateway crash", &mut forward, &sandboxes).await;

    let restarted = gateway_pods().await;
    kubectl(&["-n", &release_namespace(), "rollout", "restart", &gateway]).await;
    rollout("status", &gateway).await;
    let branches = assert_tree("gateway rolling restart", &routes, &restarted).await;
    assert_exec("gateway rolling restart", &mut forward, &sandboxes).await;

    let crashed = vec![branches[0].member.clone()];
    force_delete(&crashed[0]).await;
    rollout("status", &supervisor).await;
    assert_tree("supervisor crash", &routes, &crashed).await;
    assert_exec("supervisor crash", &mut forward, &sandboxes).await;

    forward.ensure().await;
    drop(sandboxes);
}
