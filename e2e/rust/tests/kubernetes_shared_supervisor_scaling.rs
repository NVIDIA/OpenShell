// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-shared-supervisor-scaling")]

//! Scaling the shared supervisor pool (`supervisor_topology = "gateway"`, which
//! always runs as a high-availability pool) from one member to two and back to
//! one, with `helm upgrade --set supervisor.replicas=N` of the installed
//! release.
//!
//! The release starts as a one-member pool (ci/values-supervisor-ha-scaling.yaml).
//! Scaling up adds a member and moves nothing: a live owner keeps its
//! sandboxes. Scaling down removes a member that owns a sandbox; it leaves
//! the pool, and the remaining member adopts its sandboxes. Throughout, every
//! sandbox keeps its workload Pod, runtime generation, main process, and the
//! counter that lives only in that process's memory; exec and
//! policy-mediated networking answer, with failures bounded to the hand-off;
//! and neither the gateway nor the remaining supervisor Pod is replaced,
//! since scaling the pool changes only the supervisor Deployment's replica
//! count.
//!
//! The test upgrades the release it runs against, so it needs a release of
//! its own (`mise run e2e:kubernetes:shared-supervisor-scaling`).

mod shared_supervisor;

use std::collections::BTreeMap;
use std::process::Stdio;
use std::time::Duration;

use futures_util::future::join_all;
use openshell_e2e::harness::sandbox::SandboxGuard;
use shared_supervisor::{
    GATEWAY_SELECTOR, HostEndpoint, MainProcess, SUPERVISOR_COMPONENT, TAKEOVER, call_host,
    counts_past, create, gateway_log_lines, generation, helm_command, is_takeover, kubectl_json,
    main_process, owner_of, policy, release_namespace, supervisor_pod_items, supervisor_pods,
    try_call_host, wait_for_owner, wait_until_attached,
};
use tokio::time::Instant;

/// Sandboxes created, at most, until one lands on the new member. The ring
/// places each sandbox by its random server-assigned ID, so placements can
/// cluster on one member for many sandboxes in a row; the bound must not
/// assume they alternate (eight in a row on one member was seen live).
const PLACEMENT_ATTEMPTS: usize = 32;
/// Bound on one `helm upgrade --wait`.
const HELM_TIMEOUT: Duration = Duration::from_mins(6);
/// Bound on the pool reaching its new size once Helm returns: a removed
/// member leaves within its 60-second grace period.
const CONVERGENCE_TIMEOUT: Duration = Duration::from_mins(3);
/// Interval between probes of each sandbox.
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
/// Probing continues this long after the pool reached its new size.
const SETTLE: Duration = Duration::from_secs(15);
/// Longest a sandbox whose supervisor stays may go without a successful
/// probe: brief reconnects only.
const STAYING_OUTAGE: Duration = Duration::from_secs(30);
/// Longest a sandbox handed to another member may go without a successful
/// probe; within the pool's 60-second recovery timeout.
const MOVING_OUTAGE: Duration = Duration::from_mins(1);
const POOL_MEMBER_ENV: &str = "OPENSHELL_SUPERVISOR_POOL_MEMBER_ID";

fn required_env(name: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            panic!(
                "{name} must be set; e2e/with-kube-gateway.sh sets it for the release it installs"
            )
        })
}

/// The release's shared supervisor Deployment.
async fn supervisor_deployment() -> serde_json::Value {
    let list = kubectl_json(&[
        "-n",
        &release_namespace(),
        "get",
        "deployments",
        "-l",
        SUPERVISOR_COMPONENT,
        "-o",
        "json",
    ])
    .await;
    let [deployment] = list["items"]
        .as_array()
        .expect("Deployment items")
        .as_slice()
    else {
        panic!("expected one shared supervisor Deployment: {list}");
    };
    deployment.clone()
}

/// What scaling the pool must leave alone: the gateway workloads (their
/// generation and config checksum), the gateway Pods (UID and restarts), and
/// the supervisor Pod template.
#[derive(Debug, PartialEq, Eq)]
struct Untouched {
    gateway_workloads: Vec<(String, i64, String)>,
    gateway_pods: Vec<(String, String, i64)>,
    supervisor_template: serde_json::Value,
}

async fn untouched() -> Untouched {
    let namespace = release_namespace();
    let selector = format!("{GATEWAY_SELECTOR},app.kubernetes.io/component!=supervisor");
    let workloads = kubectl_json(&[
        "-n",
        &namespace,
        "get",
        "statefulsets,deployments",
        "-l",
        &selector,
        "-o",
        "json",
    ])
    .await;
    let mut gateway_workloads = workloads["items"]
        .as_array()
        .expect("workload items")
        .iter()
        .map(|workload| {
            (
                format!(
                    "{}/{}",
                    workload["kind"].as_str().unwrap_or_default(),
                    workload["metadata"]["name"].as_str().unwrap_or_default()
                ),
                workload["metadata"]["generation"].as_i64().unwrap_or(-1),
                workload["spec"]["template"]["metadata"]["annotations"]["checksum/gateway-config"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
        .collect::<Vec<_>>();
    gateway_workloads.sort();
    assert!(
        !gateway_workloads.is_empty(),
        "no gateway workload matches {selector}"
    );
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
    let mut gateway_pods = pods["items"]
        .as_array()
        .expect("Pod items")
        .iter()
        .map(|pod| {
            (
                pod["metadata"]["name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                pod["metadata"]["uid"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                pod["status"]["containerStatuses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|status| status["restartCount"].as_i64())
                    .sum(),
            )
        })
        .collect::<Vec<_>>();
    gateway_pods.sort();
    assert!(
        !gateway_pods.is_empty(),
        "no gateway Pods match {GATEWAY_SELECTOR}"
    );
    Untouched {
        gateway_workloads,
        gateway_pods,
        supervisor_template: supervisor_deployment().await["spec"]["template"].clone(),
    }
}

/// UIDs of the running supervisor Pods, by name.
async fn running_members() -> BTreeMap<String, String> {
    let running = supervisor_pods().await;
    supervisor_pod_items()
        .await
        .iter()
        .filter_map(|pod| {
            let name = pod["metadata"]["name"].as_str()?.to_string();
            running.contains(&name).then(|| {
                (
                    name,
                    pod["metadata"]["uid"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            })
        })
        .collect()
}

/// Upgrade the release to `replicas` pool members with its own values and
/// the exact chart it was installed from, then wait until exactly that many
/// members run and no removed member is still leaving.
async fn scale_pool(replicas: usize) -> BTreeMap<String, String> {
    let release = required_env("OPENSHELL_E2E_KUBE_RELEASE");
    let chart = required_env("OPENSHELL_E2E_KUBE_CHART");
    let namespace = release_namespace();
    let replicas_value = format!("supervisor.replicas={replicas}");
    let args = [
        "upgrade",
        release.as_str(),
        chart.as_str(),
        "--namespace",
        namespace.as_str(),
        "--reuse-values",
        "--set",
        replicas_value.as_str(),
        "--wait",
        "--timeout",
        "5m",
    ];
    let output = tokio::time::timeout(
        HELM_TIMEOUT,
        helm_command()
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .unwrap_or_else(|_| panic!("helm {args:?} did not finish within {HELM_TIMEOUT:?}"))
    .unwrap_or_else(|error| panic!("spawn helm {args:?}: {error}"));
    assert!(
        output.status.success(),
        "helm {args:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(CONVERGENCE_TIMEOUT, async {
        loop {
            let pods = supervisor_pod_items().await;
            let members = running_members().await;
            if members.len() == replicas && pods.len() == replicas {
                return members;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the supervisor pool did not settle at {replicas} members"))
}

/// What the probes of one sandbox saw during a transition.
#[derive(Debug, Default)]
struct Samples {
    exec_ok: usize,
    exec_failures: Vec<String>,
    network_ok: usize,
    network_failures: Vec<String>,
    /// Longest time without a successful exec probe.
    exec_outage: Duration,
    /// Longest time without a successful network probe.
    network_outage: Duration,
    last: Option<MainProcess>,
}

/// Probe `sandbox` every [`PROBE_INTERVAL`] until `stop`: its main process
/// must stay `baseline`'s and its counter must never go back; record how
/// long exec and the policy-mediated call to the host endpoint fail.
async fn sample(
    sandbox: &SandboxGuard,
    baseline: &MainProcess,
    port: u16,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> Samples {
    let mut samples = Samples::default();
    let mut last_exec = Instant::now();
    let mut last_network = Instant::now();
    let mut counter = baseline.counter;
    loop {
        match main_process(sandbox).await {
            Ok(current) => {
                assert_eq!(
                    (current.pid, current.start_ticks),
                    (baseline.pid, baseline.start_ticks),
                    "{}'s main process was replaced: {baseline:?} then {current:?}",
                    sandbox.name
                );
                assert!(
                    current.counter >= counter,
                    "{}'s in-memory counter went back from {counter} to {}",
                    sandbox.name,
                    current.counter
                );
                counter = current.counter;
                samples.exec_outage = samples.exec_outage.max(last_exec.elapsed());
                last_exec = Instant::now();
                samples.exec_ok += 1;
                samples.last = Some(current);
            }
            Err(error) => samples.exec_failures.push(error),
        }
        match try_call_host(sandbox, port).await {
            Ok(result) if result == "HA_OK" => {
                samples.network_outage = samples.network_outage.max(last_network.elapsed());
                last_network = Instant::now();
                samples.network_ok += 1;
            }
            Ok(result) => samples.network_failures.push(result),
            Err(error) => samples.network_failures.push(error),
        }
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            () = tokio::time::sleep(PROBE_INTERVAL) => {}
            _ = stop.changed() => {}
        }
    }
    samples.exec_outage = samples.exec_outage.max(last_exec.elapsed());
    samples.network_outage = samples.network_outage.max(last_network.elapsed());
    samples
}

/// Run `transition` while probing every sandbox, and keep probing for
/// [`SETTLE`] after it finished.
async fn while_probing<T>(
    sandboxes: &[(&SandboxGuard, MainProcess)],
    port: u16,
    transition: impl Future<Output = T>,
) -> (T, Vec<Samples>) {
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let samplers = join_all(
        sandboxes
            .iter()
            .map(|(sandbox, baseline)| sample(sandbox, baseline, port, stopped.clone())),
    );
    let driver = async {
        let outcome = transition.await;
        tokio::time::sleep(SETTLE).await;
        stop.send_replace(true);
        outcome
    };
    tokio::join!(driver, samplers)
}

/// Check what the probes of `sandbox` saw against `bound`.
fn check_samples(phase: &str, sandbox: &SandboxGuard, samples: &Samples, bound: Duration) {
    eprintln!(
        "{phase}: {} exec {} ok / {} failed (longest outage {:?}), network {} ok / {} failed (longest outage {:?})",
        sandbox.name,
        samples.exec_ok,
        samples.exec_failures.len(),
        samples.exec_outage,
        samples.network_ok,
        samples.network_failures.len(),
        samples.network_outage
    );
    assert!(
        samples.exec_ok > 0 && samples.network_ok > 0,
        "{phase}: {} never answered: {samples:?}",
        sandbox.name
    );
    assert!(
        samples.exec_outage <= bound,
        "{phase}: exec on {} failed for {:?}, longer than {bound:?}: {:?}",
        sandbox.name,
        samples.exec_outage,
        samples.exec_failures
    );
    assert!(
        samples.network_outage <= bound,
        "{phase}: networking from {} failed for {:?}, longer than {bound:?}: {:?}",
        sandbox.name,
        samples.network_outage,
        samples.network_failures
    );
}

/// A sandbox under test and what it must keep.
struct Tracked {
    sandbox: SandboxGuard,
    generation: shared_supervisor::Generation,
    baseline: MainProcess,
}

impl Tracked {
    async fn new(sandbox: SandboxGuard) -> Self {
        let generation = generation(&sandbox.name).await;
        let baseline = tokio::time::timeout(Duration::from_mins(1), async {
            loop {
                if let Ok(baseline) = main_process(&sandbox).await {
                    return baseline;
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{}'s main process did not answer", sandbox.name));
        Self {
            sandbox,
            generation,
            baseline,
        }
    }

    /// Same workload Pod, generation, and main process, which counted past
    /// its baseline; networking answers. Moves the baseline forward.
    async fn check_continuity(&mut self, phase: &str, port: u16) {
        assert_eq!(
            generation(&self.sandbox.name).await,
            self.generation,
            "{phase}: {}'s workload Pod or runtime generation changed",
            self.sandbox.name
        );
        self.baseline = counts_past(&self.sandbox, &self.baseline).await;
        assert_eq!(
            call_host(&self.sandbox, port).await,
            "HA_OK",
            "{phase}: {} cannot reach the host endpoint through its policy",
            self.sandbox.name
        );
    }
}

/// Delete every sandbox in `tracked`, then fail with every delete error.
async fn delete_all(tracked: Vec<Tracked>) {
    let mut failures = Vec::new();
    for mut sandbox in tracked.into_iter().map(|tracked| tracked.sandbox) {
        if let Err(error) = sandbox.delete().await {
            failures.push(error);
        }
    }
    assert!(
        failures.is_empty(),
        "could not delete sandboxes: {failures:#?}"
    );
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn scaling_a_supervisor_pool_up_and_down_keeps_its_sandboxes_running() {
    // A one-member pool: pool mode is chosen explicitly, not by the count.
    let initial = running_members().await;
    assert_eq!(
        initial.len(),
        1,
        "the release must start with one supervisor pool member: {initial:?}"
    );
    let first_member = initial.keys().next().expect("one member").clone();
    wait_until_attached(std::slice::from_ref(&first_member)).await;
    let before = untouched().await;
    assert!(
        before.supervisor_template["spec"]["containers"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|container| container["env"].as_array().into_iter().flatten())
            .any(|env| env["name"] == POOL_MEMBER_ENV),
        "the shared supervisor Pod template carries no pool member identity; install the chart from this branch"
    );
    let endpoint = HostEndpoint::start().await;
    let policy = policy(endpoint.port);

    // Phase 1: one member supervises a sandbox.
    let mut a = Tracked::new(create(&policy).await).await;
    assert_eq!(wait_for_owner(&a.generation.route).await, first_member);
    a.check_continuity("one member", endpoint.port).await;

    // Phase 2: scale to two members. The new member joins; nothing moves.
    let (two_members, samples) = while_probing(
        &[(&a.sandbox, a.baseline.clone())],
        endpoint.port,
        scale_pool(2),
    )
    .await;
    check_samples("scale up", &a.sandbox, &samples[0], STAYING_OUTAGE);
    assert_eq!(
        two_members.get(&first_member),
        initial.get(&first_member),
        "scaling up replaced the first member: {two_members:?}"
    );
    let second_member = two_members
        .keys()
        .find(|member| **member != first_member)
        .expect("a second member")
        .clone();
    wait_until_attached(&[first_member.clone(), second_member.clone()]).await;
    assert_eq!(
        untouched().await,
        before,
        "scaling up changed the gateway or the supervisor template"
    );
    assert_eq!(
        wait_for_owner(&a.generation.route).await,
        first_member,
        "a live owner keeps its sandbox when the pool grows"
    );
    assert!(
        gateway_log_lines(&a.generation.route)
            .await
            .iter()
            .all(|line| !line.contains(TAKEOVER)),
        "scaling up moved {}",
        a.sandbox.name
    );
    a.check_continuity("two members", endpoint.port).await;

    // A new sandbox lands on the new member; others the ring places on the
    // first member are removed again.
    let mut b = None;
    for _ in 0..PLACEMENT_ATTEMPTS {
        let candidate = Tracked::new(create(&policy).await).await;
        if wait_for_owner(&candidate.generation.route).await == second_member {
            b = Some(candidate);
            break;
        }
        delete_all(vec![candidate]).await;
    }
    let mut b = b.unwrap_or_else(|| {
        panic!(
            "the pool placed {PLACEMENT_ATTEMPTS} new sandboxes on {first_member}, none on {second_member}"
        )
    });
    b.check_continuity("two members", endpoint.port).await;
    eprintln!(
        "{} on {first_member}, {} on {second_member}",
        a.sandbox.name, b.sandbox.name
    );

    // Phase 3: scale back to one member. Each member owns a sandbox, so the
    // member that leaves hands at least one live sandbox to the other.
    let owners_before = BTreeMap::from([
        (a.generation.route.clone(), first_member.clone()),
        (b.generation.route.clone(), second_member.clone()),
    ]);
    let (members, samples) = while_probing(
        &[
            (&a.sandbox, a.baseline.clone()),
            (&b.sandbox, b.baseline.clone()),
        ],
        endpoint.port,
        scale_pool(1),
    )
    .await;
    let (survivor, survivor_uid) = members.into_iter().next().expect("one member");
    let leaver = if survivor == first_member {
        second_member.clone()
    } else {
        first_member.clone()
    };
    assert_eq!(
        two_members.get(&survivor),
        Some(&survivor_uid),
        "scaling down replaced the remaining member"
    );
    eprintln!("{leaver} left the pool; {survivor} remains");
    wait_until_attached(std::slice::from_ref(&survivor)).await;
    assert_eq!(
        untouched().await,
        before,
        "scaling down changed the gateway or the supervisor template"
    );
    let handed_off = owners_before
        .iter()
        .filter(|(_, owner)| **owner == leaver)
        .map(|(route, _)| route.clone())
        .collect::<Vec<_>>();
    assert!(
        !handed_off.is_empty(),
        "{leaver} owned no sandbox to hand off"
    );
    for (tracked, samples) in [&a, &b].into_iter().zip(&samples) {
        let moved = handed_off.contains(&tracked.generation.route);
        check_samples(
            if moved {
                "scale down (handed off)"
            } else {
                "scale down (stayed)"
            },
            &tracked.sandbox,
            samples,
            if moved { MOVING_OUTAGE } else { STAYING_OUTAGE },
        );
    }
    for route in &handed_off {
        assert_eq!(
            wait_for_owner(route).await,
            survivor,
            "the remaining member must adopt {route}"
        );
        let takeover = gateway_log_lines(route).await;
        assert!(
            takeover
                .iter()
                .any(|line| is_takeover(line, route, &leaver, "leaving")),
            "no gateway handed {route} over from {leaver} as a leaving member: {takeover:?}"
        );
    }
    for (route, owner) in &owners_before {
        if *owner == survivor {
            assert_eq!(
                owner_of(route).await.as_deref(),
                Some(survivor.as_str()),
                "the remaining member's own sandbox must stay with it"
            );
        }
    }
    a.check_continuity("back to one member", endpoint.port)
        .await;
    b.check_continuity("back to one member", endpoint.port)
        .await;

    // A sandbox created after scaling down runs on the remaining member.
    let mut c = Tracked::new(create(&policy).await).await;
    assert_eq!(wait_for_owner(&c.generation.route).await, survivor);
    c.check_continuity("back to one member", endpoint.port)
        .await;
    for tracked in [&mut a, &mut b] {
        tracked.check_continuity("final", endpoint.port).await;
    }
    assert_eq!(
        untouched().await,
        before,
        "the gateway or the supervisor template changed"
    );

    delete_all(vec![a, b, c]).await;
}
