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

mod shared_supervisor;

use std::process::Stdio;
use std::time::Duration;

use shared_supervisor::{
    HostEndpoint, SUPERVISOR_CONTAINER, call_host, counts_past, create, gateway_log_lines,
    generation, is_takeover, kubectl, kubectl_command, kubectl_json, main_process, owner_of,
    policy, release_namespace, supervisor_pods, wait_for_owner, wait_until_attached,
};
use tokio::io::AsyncBufReadExt as _;

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
