// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-ha")]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use futures_util::future::try_join_all;
use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

static KUBE_HA_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const HA_SYNC_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;
const HA_SYNC_TIMEOUT: Duration = Duration::from_secs(600);

const HA_REDISTRIBUTION_SANDBOXES: usize = 4;
/// Overall budget for the rollout test. It stays below the 600 s nextest
/// terminate-after limit so a slow step fails with its own diagnostics
/// instead of a bare timeout.
const HA_REDISTRIBUTION_TEST_BUDGET: Duration = Duration::from_secs(540);
// Per-step caps; each step also stops at the overall deadline.
const HA_REDISTRIBUTION_CREATE_TIMEOUT: Duration = Duration::from_secs(180);
const HA_SESSION_ACCOUNTING_TIMEOUT: Duration = Duration::from_secs(90);
const HA_ROLLOUT_TIMEOUT: Duration = Duration::from_secs(180);
/// Old pods can still be draining after `rollout status` returns; the drain
/// plus cleanup takes at most 25 s.
const HA_DRAIN_EXIT_TIMEOUT: Duration = Duration::from_secs(30);
/// A drained gateway pod leaves the pod list within that 25 s bound plus pod
/// teardown and one poll. A pod still listed after this long overran the
/// bound or was killed at the end of its 30 s termination grace period.
const HA_DRAIN_EXIT_BOUND: Duration = Duration::from_secs(28);
const HA_READY_PODS_TIMEOUT: Duration = Duration::from_secs(120);
const HA_EXEC_TIMEOUT: Duration = Duration::from_secs(180);
/// Bounds the wait for a scaled-down pod's sandboxes to report Ready again.
const HA_SETTLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Bounds one metrics scrape or sandbox listing, so a hung call cannot run
/// past a step deadline.
const HA_QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const SUPERVISOR_SESSIONS_METRIC: &str = "openshell_server_supervisor_sessions";
const DRAINING_METRIC: &str = "openshell_server_draining";
const RELAY_PENDING_CAPACITY_METRIC: &str = "openshell_server_relay_pending_capacity";
const RELAY_PENDING_CAPACITY: u64 = 256;

#[derive(Clone)]
struct KubeTarget {
    context: String,
    namespace: String,
    release: String,
}

impl KubeTarget {
    fn from_env() -> Self {
        Self {
            context: required_env("OPENSHELL_E2E_KUBE_CONTEXT"),
            namespace: std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE")
                .unwrap_or_else(|_| "openshell".to_string()),
            release: std::env::var("OPENSHELL_E2E_KUBE_RELEASE")
                .unwrap_or_else(|_| "openshell".to_string()),
        }
    }

    async fn kubectl(&self, args: &[&str]) -> Result<String, String> {
        let output = Command::new("kubectl")
            .arg("--context")
            .arg(&self.context)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|err| format!("failed to spawn kubectl {args:?}: {err}"))?;

        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        if !output.status.success() {
            return Err(format!(
                "kubectl {args:?} failed with exit {:?}:\n{combined}",
                output.status.code()
            ));
        }

        Ok(combined)
    }

    async fn scale_gateway(&self, replicas: usize) -> Result<(), String> {
        let resource = self.gateway_workload_resource().await?;
        let replicas_arg = replicas.to_string();

        self.kubectl(&[
            "-n",
            &self.namespace,
            "scale",
            &resource,
            "--replicas",
            &replicas_arg,
        ])
        .await?;
        self.kubectl(&[
            "-n",
            &self.namespace,
            "rollout",
            "status",
            &resource,
            "--timeout=180s",
        ])
        .await?;
        Ok(())
    }

    async fn gateway_workload_resource(&self) -> Result<String, String> {
        let deployment = format!("deployment/{}", self.release);
        if self
            .kubectl(&["-n", &self.namespace, "get", &deployment])
            .await
            .is_ok()
        {
            return Ok(deployment);
        }

        let statefulset = format!("statefulset/{}", self.release);
        if self
            .kubectl(&["-n", &self.namespace, "get", &statefulset])
            .await
            .is_ok()
        {
            return Ok(statefulset);
        }

        Err(format!(
            "no gateway Deployment or StatefulSet named {} found in namespace {}",
            self.release, self.namespace
        ))
    }

    async fn delete_gateway_pod(&self, pod: &str) -> Result<(), String> {
        self.kubectl(&[
            "-n",
            &self.namespace,
            "delete",
            "pod",
            pod,
            "--wait=true",
            "--timeout=90s",
        ])
        .await?;
        Ok(())
    }

    async fn roll_gateway_pods(&self, pods: Vec<String>, expected: usize) -> Result<(), String> {
        for pod in pods {
            self.delete_gateway_pod(&pod).await?;
            self.wait_for_gateway_pods(expected).await?;
        }
        Ok(())
    }

    async fn wait_for_gateway_pods(&self, expected: usize) -> Result<Vec<String>, String> {
        self.wait_for_gateway_pods_until(expected, Instant::now() + Duration::from_secs(240))
            .await
    }

    async fn wait_for_gateway_pods_until(
        &self,
        expected: usize,
        deadline: Instant,
    ) -> Result<Vec<String>, String> {
        let budget = deadline.saturating_duration_since(Instant::now());
        let mut last = String::new();

        while Instant::now() < deadline {
            match self.gateway_pods().await {
                Ok(pods) => {
                    if pods.len() == expected && pods.iter().all(|pod| pod.ready) {
                        return Ok(pods.into_iter().map(|pod| pod.name).collect());
                    }
                    last = format!(
                        "pods={:?}",
                        pods.iter()
                            .map(|pod| format!("{} ready={}", pod.name, pod.ready))
                            .collect::<Vec<_>>()
                    );
                }
                Err(err) => last = err,
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Err(format!(
            "gateway pods did not reach expected ready count {expected} within {budget:?}; last={last}"
        ))
    }

    async fn gateway_pods(&self) -> Result<Vec<GatewayPod>, String> {
        Ok(self
            .gateway_pod_states()
            .await?
            .into_iter()
            .filter(|pod| !pod.terminating)
            .collect())
    }

    /// Every gateway pod, including pods that are terminating.
    async fn gateway_pod_states(&self) -> Result<Vec<GatewayPod>, String> {
        let selector = format!("app.kubernetes.io/instance={}", self.release);
        // Bound each poll so a stalled API server cannot push a step past its
        // deadline.
        let request_timeout = format!("--request-timeout={}s", HA_QUERY_TIMEOUT.as_secs());
        let json = self
            .kubectl(&[
                &request_timeout,
                "-n",
                &self.namespace,
                "get",
                "pods",
                "-l",
                &selector,
                "-o",
                "json",
            ])
            .await?;
        let value = serde_json::from_str::<Value>(&json)
            .map_err(|err| format!("failed to parse gateway pod JSON: {err}\n{json}"))?;
        let items = value["items"]
            .as_array()
            .ok_or_else(|| format!("gateway pod JSON missing items array: {value}"))?;

        let mut pods = Vec::new();
        for item in items {
            let Some(name) = item["metadata"]["name"].as_str() else {
                continue;
            };
            let ready = item["status"]["conditions"]
                .as_array()
                .is_some_and(|conditions| {
                    conditions.iter().any(|condition| {
                        condition["type"].as_str() == Some("Ready")
                            && condition["status"].as_str() == Some("True")
                    })
                });
            let metrics_port = item["spec"]["containers"]
                .as_array()
                .and_then(|containers| {
                    containers
                        .iter()
                        .filter_map(|container| container["ports"].as_array())
                        .flatten()
                        .find(|port| port["name"].as_str() == Some("metrics"))
                })
                .and_then(|port| port["containerPort"].as_u64())
                .and_then(|port| u16::try_from(port).ok());
            pods.push(GatewayPod {
                name: name.to_string(),
                ready,
                terminating: !item["metadata"]["deletionTimestamp"].is_null(),
                metrics_port,
            });
        }
        pods.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pods)
    }

    /// Run `kubectl get --raw` and return stdout only, so stderr warnings
    /// cannot corrupt the response body.
    async fn kubectl_raw(&self, path: &str) -> Result<String, String> {
        let request_timeout = format!("--request-timeout={}s", HA_QUERY_TIMEOUT.as_secs());
        let output = Command::new("kubectl")
            .arg("--context")
            .arg(&self.context)
            .args([request_timeout.as_str(), "get", "--raw", path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output()
            .await
            .map_err(|err| format!("failed to spawn kubectl get --raw {path}: {err}"))?;

        if !output.status.success() {
            return Err(format!(
                "kubectl get --raw {path} failed with exit {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }

        String::from_utf8(output.stdout)
            .map_err(|err| format!("kubectl get --raw {path} returned non-UTF-8 output: {err}"))
    }

    /// Fetch `/metrics` through the API server's pod proxy, which reaches the
    /// plain-HTTP metrics listener without a port-forward.
    async fn scrape_gateway_metrics(&self, pod: &GatewayPod) -> Result<String, String> {
        let port = pod.metrics_port.ok_or_else(|| {
            format!(
                "gateway pod {} has no container port named metrics",
                pod.name
            )
        })?;
        self.kubectl_raw(&format!(
            "/api/v1/namespaces/{}/pods/{}:{port}/proxy/metrics",
            self.namespace, pod.name
        ))
        .await
    }

    /// No terminating gateway pod, exactly `expected_pods` ready pods, and
    /// every `required` sandbox in phase Ready. Returns the pods and the full
    /// phase map.
    async fn gateway_settled_once(
        &self,
        expected_pods: usize,
        required: &[String],
    ) -> Result<(Vec<GatewayPod>, BTreeMap<String, String>), String> {
        let pods = self.gateway_pod_states().await?;
        if pods.len() != expected_pods || pods.iter().any(|pod| pod.terminating || !pod.ready) {
            return Err(format!(
                "expected {expected_pods} ready gateway pods and none terminating; pods={:?}",
                pods.iter()
                    .map(|pod| format!(
                        "{} ready={} terminating={}",
                        pod.name, pod.ready, pod.terminating
                    ))
                    .collect::<Vec<_>>()
            ));
        }

        let phases = sandbox_phases().await?;
        let not_ready: Vec<String> = required
            .iter()
            .filter(|name| phases.get(*name).map(String::as_str) != Some("Ready"))
            .map(|name| {
                format!(
                    "{name}={}",
                    phases.get(name).map_or("missing", String::as_str)
                )
            })
            .collect();
        if !not_ready.is_empty() {
            return Err(format!(
                "sandboxes not Ready: {not_ready:?}; phases={phases:?}"
            ));
        }
        Ok((pods, phases))
    }

    async fn wait_for_gateway_settled(
        &self,
        expected_pods: usize,
        required: &[String],
        deadline: Instant,
    ) -> Result<(), String> {
        poll_until(
            deadline,
            "gateway pods and sandboxes did not settle",
            move || self.gateway_settled_once(expected_pods, required),
        )
        .await
        .map(|_| ())
    }

    /// Settled gateway, and on every pod: the relay capacity gauge, draining
    /// at 0, and supervisor sessions that add up to the Ready sandbox count.
    async fn session_accounting_once(
        &self,
        expected_pods: usize,
        required: &[String],
    ) -> Result<SessionAccounting, String> {
        let (pods, phases) = self.gateway_settled_once(expected_pods, required).await?;
        let mut sessions_by_pod = BTreeMap::new();
        for pod in &pods {
            let metrics = self.scrape_gateway_metrics(pod).await?;
            let capacity = prometheus_count(&metrics, RELAY_PENDING_CAPACITY_METRIC)?;
            if capacity != RELAY_PENDING_CAPACITY {
                return Err(format!(
                    "{RELAY_PENDING_CAPACITY_METRIC} on {} is {capacity}, expected {RELAY_PENDING_CAPACITY}",
                    pod.name
                ));
            }
            let draining = prometheus_count(&metrics, DRAINING_METRIC)?;
            if draining != 0 {
                return Err(format!(
                    "{DRAINING_METRIC} on ready pod {} is {draining}",
                    pod.name
                ));
            }
            sessions_by_pod.insert(
                pod.name.clone(),
                prometheus_count(&metrics, SUPERVISOR_SESSIONS_METRIC)?,
            );
        }

        let ready = phases.values().filter(|phase| *phase == "Ready").count();
        let ready_sandboxes = u64::try_from(ready).unwrap_or(u64::MAX);
        let sessions: u64 = sessions_by_pod.values().sum();
        if sessions != ready_sandboxes {
            return Err(format!(
                "supervisor sessions {sessions_by_pod:?} add up to {sessions}, but {ready_sandboxes} sandboxes are Ready; phases={phases:?}"
            ));
        }
        Ok(SessionAccounting {
            sessions_by_pod,
            ready_sandboxes,
        })
    }

    async fn wait_for_session_accounting(
        &self,
        expected_pods: usize,
        required: &[String],
        deadline: Instant,
    ) -> Result<SessionAccounting, String> {
        poll_until(
            deadline.min(Instant::now() + HA_SESSION_ACCOUNTING_TIMEOUT),
            "supervisor session gauges did not account for every Ready sandbox",
            move || self.session_accounting_once(expected_pods, required),
        )
        .await
    }

    /// Run `kubectl rollout restart` on the gateway and wait until the
    /// rollout finished and no old pod is left, recording which terminating
    /// pods reported `openshell_server_draining` 1 and how long each stayed
    /// terminating. `rollout status` returns while old pods may still drain,
    /// because terminating pods do not count toward Deployment status.
    async fn restart_gateway_and_observe_drain(
        &self,
        deadline: Instant,
    ) -> Result<RolloutObservation, String> {
        let resource = self.gateway_workload_resource().await?;
        self.kubectl(&["-n", &self.namespace, "rollout", "restart", &resource])
            .await?;

        let status_timeout = format!(
            "--timeout={}s",
            step_budget(deadline, HA_ROLLOUT_TIMEOUT).as_secs().max(1)
        );
        let status_args = [
            "-n",
            &self.namespace,
            "rollout",
            "status",
            &resource,
            &status_timeout,
        ];
        let status = self.kubectl(&status_args);
        tokio::pin!(status);

        let until = deadline.min(Instant::now() + HA_ROLLOUT_TIMEOUT + HA_DRAIN_EXIT_TIMEOUT);
        let mut observation = RolloutObservation::default();
        let mut status_done = false;
        // Pods still listed as terminating, each with the end of the first
        // listing that showed it terminating.
        let mut first_seen: BTreeMap<String, Instant> = BTreeMap::new();
        loop {
            if Instant::now() >= until {
                return Err(format!(
                    "rollout status finished={status_done}; pods still terminating={:?}; {observation:?}",
                    first_seen.keys().collect::<Vec<_>>()
                ));
            }
            if status_done {
                tokio::time::sleep(Duration::from_millis(500)).await;
            } else {
                tokio::select! {
                    result = &mut status => {
                        result.map_err(|err| format!("{err}\n{observation:?}"))?;
                        status_done = true;
                    }
                    () = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }

            let listing_started = Instant::now();
            // Pods churn during a rollout; retry on the next tick.
            let Ok(pods) = self.gateway_pod_states().await else {
                continue;
            };
            let listed_at = Instant::now();
            let terminating: Vec<&GatewayPod> = pods.iter().filter(|pod| pod.terminating).collect();
            let names: Vec<&str> = terminating.iter().map(|pod| pod.name.as_str()).collect();
            record_terminating_pods(
                &mut first_seen,
                &mut observation.exit_times,
                &names,
                listing_started,
                listed_at,
            );
            for pod in terminating {
                observation.terminating.insert(pod.name.clone());
                // The process may already have exited; only a positive
                // reading counts. Stop scraping a pod after one, which keeps
                // each poll short and its exit time accurate.
                if !observation.draining.contains(&pod.name)
                    && self
                        .scrape_gateway_metrics(pod)
                        .await
                        .is_ok_and(|metrics| prometheus_count(&metrics, DRAINING_METRIC) == Ok(1))
                {
                    observation.draining.insert(pod.name.clone());
                }
            }
            if status_done && first_seen.is_empty() {
                return Ok(observation);
            }
        }
    }

    /// Unwrap a step result, or panic with its error followed by a snapshot of
    /// the gateway pods and sandboxes.
    async fn check<T>(&self, what: &str, result: Result<T, String>) -> T {
        match result {
            Ok(value) => value,
            Err(err) => panic!("{what}: {err}\n{}", self.diagnostics().await),
        }
    }

    /// Best-effort snapshot for failure messages: each gateway pod with its
    /// state and session and draining gauges, then every sandbox phase.
    async fn diagnostics(&self) -> String {
        let mut out = String::from("cluster snapshot:");
        match self.gateway_pod_states().await {
            Ok(pods) => {
                for pod in &pods {
                    let gauges = match self.scrape_gateway_metrics(pod).await {
                        Ok(metrics) => {
                            let gauge = |metric| {
                                prometheus_count(&metrics, metric)
                                    .map_or_else(|err| err, |value| value.to_string())
                            };
                            format!(
                                "sessions={} draining={}",
                                gauge(SUPERVISOR_SESSIONS_METRIC),
                                gauge(DRAINING_METRIC)
                            )
                        }
                        Err(err) => format!("metrics unavailable: {err}"),
                    };
                    let _ = write!(
                        out,
                        "\n  gateway pod {} ready={} terminating={} {gauges}",
                        pod.name, pod.ready, pod.terminating
                    );
                }
            }
            Err(err) => {
                let _ = write!(out, "\n  gateway pods unavailable: {err}");
            }
        }
        match sandbox_phases().await {
            Ok(phases) => {
                let _ = write!(out, "\n  sandbox phases: {phases:?}");
            }
            Err(err) => {
                let _ = write!(out, "\n  sandbox phases unavailable: {err}");
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
struct GatewayPod {
    name: String,
    ready: bool,
    /// `metadata.deletionTimestamp` is set.
    terminating: bool,
    /// `containerPort` of the container port named `metrics`.
    metrics_port: Option<u16>,
}

#[derive(Debug)]
struct SessionAccounting {
    sessions_by_pod: BTreeMap<String, u64>,
    ready_sandboxes: u64,
}

#[derive(Debug, Default)]
struct RolloutObservation {
    terminating: BTreeSet<String>,
    draining: BTreeSet<String>,
    /// For each pod seen terminating: from the end of the first listing that
    /// showed it terminating to the start of the first listing without it. A
    /// late first sighting only shortens this; the last poll adds at most
    /// one poll interval.
    exit_times: BTreeMap<String, Duration>,
}

struct PortForward {
    port: u16,
    child: Child,
}

impl PortForward {
    async fn start(kube: &KubeTarget, pod: &str) -> Result<Self, String> {
        let port = find_free_port();
        let mut child = Command::new("kubectl")
            .arg("--context")
            .arg(&kube.context)
            .arg("-n")
            .arg(&kube.namespace)
            .arg("port-forward")
            .arg(format!("pod/{pod}"))
            .arg(format!("{port}:8080"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| format!("failed to start kubectl port-forward for {pod}: {err}"))?;

        match wait_for_port("127.0.0.1", port, Duration::from_secs(30)).await {
            Ok(()) => Ok(Self { port, child }),
            Err(err) => {
                let status = child.try_wait().ok().flatten();
                let _ = child.kill().await;
                Err(format!(
                    "port-forward to {pod} did not become ready on {port}: {err}; status={status:?}"
                ))
            }
        }
    }
}

impl Drop for PortForward {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is not set; run through e2e/rust/e2e-kubernetes.sh"))
}

async fn exec_through_pod(
    kube: &KubeTarget,
    pod: &str,
    sandbox_name: &str,
    marker: &str,
) -> Result<(), String> {
    let port_forward = PortForward::start(kube, pod).await?;
    let endpoint = format!("http://127.0.0.1:{}", port_forward.port);

    let mut cmd = openshell_cmd();
    cmd.arg("--gateway-endpoint")
        .arg(&endpoint)
        .args([
            "sandbox",
            "exec",
            "--name",
            sandbox_name,
            "--no-tty",
            "--",
            "printf",
            "%s",
            marker,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|err| format!("failed to spawn openshell exec via {pod}: {err}"))?;

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    if !output.status.success() || !combined.contains(marker) {
        return Err(format!(
            "exec through {pod} ({endpoint}) failed with exit {:?}; expected marker {marker:?}; output:\n{combined}",
            output.status.code()
        ));
    }

    Ok(())
}

async fn exec_through_configured_gateway(sandbox_name: &str, marker: &str) -> Result<(), String> {
    let mut cmd = openshell_cmd();
    cmd.args([
        "sandbox",
        "exec",
        "--name",
        sandbox_name,
        "--no-tty",
        "--",
        "printf",
        "%s",
        marker,
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let output = cmd
        .output()
        .await
        .map_err(|err| format!("failed to spawn openshell exec via configured gateway: {err}"))?;

    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    if !output.status.success() || !combined.contains(marker) {
        return Err(format!(
            "exec through configured gateway failed with exit {:?}; expected marker {marker:?}; output:\n{combined}",
            output.status.code()
        ));
    }

    Ok(())
}

async fn create_sandbox_through_configured_gateway(phase: &str) -> Result<SandboxGuard, String> {
    let marker = format!("ha-create-watch-{phase}");
    let guard = SandboxGuard::create(&["--", "printf", "%s", &marker]).await?;
    let output = strip_ansi(&guard.create_output);

    if !output.contains(&marker) {
        return Err(format!(
            "sandbox create through configured gateway did not include marker {marker:?}; output:\n{output}"
        ));
    }

    Ok(guard)
}

async fn assert_exec_through_all_pods(
    kube: &KubeTarget,
    pods: &[String],
    sandbox_name: &str,
    phase: &str,
) -> Result<(), String> {
    for pod in pods {
        let marker = format!("ha-rebalance-{phase}-{pod}");
        exec_through_pod(kube, pod, sandbox_name, &marker).await?;
    }
    Ok(())
}

/// `name -> phase` for every sandbox in the CLI's workspace.
async fn sandbox_phases() -> Result<BTreeMap<String, String>, String> {
    let mut cmd = openshell_cmd();
    // The session gauge counts every workspace, so list every workspace too.
    cmd.args(["sandbox", "list", "--all-workspaces", "--output", "json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = tokio::time::timeout(HA_QUERY_TIMEOUT, cmd.output())
        .await
        .map_err(|_| format!("sandbox list did not finish within {HA_QUERY_TIMEOUT:?}"))?
        .map_err(|err| format!("failed to spawn openshell sandbox list: {err}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if !output.status.success() {
        return Err(format!(
            "sandbox list failed with exit {:?}:\n{stdout}{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let json = stdout.find('{').map_or("", |start| &stdout[start..]);
    let value = serde_json::from_str::<Value>(json)
        .map_err(|err| format!("failed to parse sandbox list JSON: {err}\n{stdout}"))?;
    if value["next_page_token"]
        .as_str()
        .is_some_and(|token| !token.is_empty())
    {
        return Err(format!(
            "sandbox list returned more than one page; the check needs every sandbox:\n{stdout}"
        ));
    }
    let sandboxes = value["sandboxes"]
        .as_array()
        .ok_or_else(|| format!("sandbox list JSON missing sandboxes array: {value}"))?;

    Ok(sandboxes
        .iter()
        .filter_map(|sandbox| {
            Some((
                sandbox["name"].as_str()?.to_string(),
                sandbox["phase"].as_str()?.to_string(),
            ))
        })
        .collect())
}

/// Value of an unlabelled sample in Prometheus text exposition output.
fn prometheus_sample(text: &str, metric: &str) -> Option<f64> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            if fields.next()? != metric {
                return None;
            }
            fields.next()?.parse::<f64>().ok()
        })
}

fn prometheus_count(text: &str, metric: &str) -> Result<u64, String> {
    let value = prometheus_sample(text, metric)
        .ok_or_else(|| format!("metric {metric} missing from /metrics"))?;
    if value < 0.0 || value.fract() != 0.0 {
        return Err(format!("metric {metric} is not a count: {value}"));
    }
    format!("{value:.0}")
        .parse::<u64>()
        .map_err(|err| format!("metric {metric} value {value}: {err}"))
}

/// Record one successful pod listing. A pod newly listed as terminating is
/// timed from `listed_at`, the end of the listing. A timed pod missing from
/// the listing left after the previous one, so its time up to
/// `listing_started` moves to `exit_times`.
fn record_terminating_pods(
    first_seen: &mut BTreeMap<String, Instant>,
    exit_times: &mut BTreeMap<String, Duration>,
    terminating: &[&str],
    listing_started: Instant,
    listed_at: Instant,
) {
    first_seen.retain(|name, seen| {
        let listed = terminating.contains(&name.as_str());
        if !listed {
            exit_times.insert(
                name.clone(),
                listing_started.saturating_duration_since(*seen),
            );
        }
        listed
    });
    for name in terminating {
        if !exit_times.contains_key(*name) {
            first_seen.entry((*name).to_string()).or_insert(listed_at);
        }
    }
}

/// Time left before `deadline`, capped at `step`.
fn step_budget(deadline: Instant, step: Duration) -> Duration {
    deadline.saturating_duration_since(Instant::now()).min(step)
}

/// Run one step under `min(step, time left)`, naming the step on timeout.
async fn within<T>(
    deadline: Instant,
    step: Duration,
    what: &str,
    fut: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    let budget = step_budget(deadline, step);
    tokio::time::timeout(budget, fut)
        .await
        .map_err(|_| format!("{what} did not finish within {budget:?}"))?
}

/// Run `attempt` at least once, then every 2 s until it succeeds or `until`
/// passes. The error names `what` and carries the last failure.
async fn poll_until<T, Fut>(
    until: Instant,
    what: &str,
    mut attempt: impl FnMut() -> Fut,
) -> Result<T, String>
where
    Fut: Future<Output = Result<T, String>>,
{
    let budget = until.saturating_duration_since(Instant::now());
    let interval = Duration::from_secs(2);
    loop {
        let last = match attempt().await {
            Ok(value) => return Ok(value),
            Err(err) => err,
        };
        if Instant::now() + interval >= until {
            return Err(format!("{what} within {budget:?}; last: {last}"));
        }
        tokio::time::sleep(interval).await;
    }
}

fn write_deterministic_payload(path: &Path, size: usize) {
    let mut file = fs::File::create(path).expect("create HA sync payload");
    let mut offset = 0usize;
    let mut remaining = size;
    let mut buf = vec![0_u8; 64 * 1024];

    while remaining > 0 {
        let chunk_len = remaining.min(buf.len());
        for (idx, byte) in buf[..chunk_len].iter_mut().enumerate() {
            *byte = u8::try_from((offset + idx) % 251).expect("byte value fits");
        }
        file.write_all(&buf[..chunk_len])
            .expect("write HA sync payload chunk");
        offset += chunk_len;
        remaining -= chunk_len;
    }
}

fn sha256_file(path: &Path) -> String {
    let data = fs::read(path).expect("read file for SHA-256");
    let mut hasher = Sha256::new();
    hasher.update(&data);
    hex::encode(hasher.finalize())
}

fn upload_command(sandbox_name: &str, local_path: &Path, dest: &str) -> Command {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("upload")
        .arg(sandbox_name)
        .arg(local_path)
        .arg(dest)
        .arg("--no-git-ignore");
    cmd
}

fn download_command(sandbox_name: &str, sandbox_path: &str, local_dest: &Path) -> Command {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("download")
        .arg(sandbox_name)
        .arg(sandbox_path)
        .arg(local_dest);
    cmd
}

async fn run_cli_during_gateway_pod_roll(
    kube: &KubeTarget,
    mut cmd: Command,
    operation: &str,
) -> Result<String, String> {
    let pods = kube.wait_for_gateway_pods(2).await?;

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = cmd
        .spawn()
        .map_err(|err| format!("failed to spawn {operation} command: {err}"))?;

    let (roll_result, output_result) = tokio::time::timeout(HA_SYNC_TIMEOUT, async {
        let roll = async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            kube.roll_gateway_pods(pods, 2).await
        };
        tokio::join!(roll, child.wait_with_output())
    })
    .await
    .map_err(|_| {
        format!(
            "{operation} command and gateway pod roll did not finish within {HA_SYNC_TIMEOUT:?}"
        )
    })?;

    roll_result.map_err(|err| {
        format!("gateway pod roll failed while {operation} command was running: {err}")
    })?;

    let output =
        output_result.map_err(|err| format!("failed to wait for {operation} command: {err}"))?;
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ));
    if !output.status.success() {
        return Err(format!(
            "{operation} command failed with exit {:?} during gateway pod roll:\n{combined}",
            output.status.code()
        ));
    }

    Ok(combined)
}

#[tokio::test]
async fn sandbox_exec_rebalances_across_gateway_scale_and_rollout() {
    let _test_lock = KUBE_HA_TEST_LOCK.lock().await;
    let kube = KubeTarget::from_env();

    let mut pods = kube
        .wait_for_gateway_pods(2)
        .await
        .expect("gateway should start with two ready HA replicas");

    let mut sandbox = create_sandbox_through_configured_gateway("initial")
        .await
        .expect("sandbox create and readiness watch should succeed through the configured gateway endpoint initially");

    assert_exec_through_all_pods(&kube, &pods, &sandbox.name, "initial")
        .await
        .expect("exec should work through every initial gateway pod");
    exec_through_configured_gateway(&sandbox.name, "ha-rebalance-client-initial")
        .await
        .expect("exec should work through the configured client gateway endpoint initially");

    kube.scale_gateway(3)
        .await
        .expect("scale gateway to three replicas");
    pods = kube
        .wait_for_gateway_pods(3)
        .await
        .expect("gateway should scale to three ready replicas");
    assert_exec_through_all_pods(&kube, &pods, &sandbox.name, "scale-up")
        .await
        .expect("exec should work through every gateway pod after scale-up");
    exec_through_configured_gateway(&sandbox.name, "ha-rebalance-client-scale-up")
        .await
        .expect("exec should work through the configured client gateway endpoint after scale-up");
    let mut scale_up_sandbox = create_sandbox_through_configured_gateway("scale-up")
        .await
        .expect(
            "sandbox create and readiness watch should succeed through the configured gateway endpoint after scale-up",
        );
    scale_up_sandbox.cleanup().await;

    kube.scale_gateway(2)
        .await
        .expect("scale gateway back to two replicas");
    pods = kube
        .wait_for_gateway_pods(2)
        .await
        .expect("gateway should scale back to two ready replicas");
    // The removed pod drains after `rollout status` returns, and new execs
    // fail while the moved sandbox briefly reports Provisioning.
    kube.wait_for_gateway_settled(
        2,
        &[sandbox.name.clone()],
        Instant::now() + HA_SETTLE_TIMEOUT,
    )
    .await
    .expect("the removed gateway pod should finish draining and the sandbox should be Ready again");
    assert_exec_through_all_pods(&kube, &pods, &sandbox.name, "scale-down")
        .await
        .expect("exec should work through every gateway pod after scale-down");
    exec_through_configured_gateway(&sandbox.name, "ha-rebalance-client-scale-down")
        .await
        .expect("exec should work through the configured client gateway endpoint after scale-down");
    let mut scale_down_sandbox = create_sandbox_through_configured_gateway("scale-down")
        .await
        .expect(
            "sandbox create and readiness watch should succeed through the configured gateway endpoint after scale-down",
        );
    scale_down_sandbox.cleanup().await;

    for (idx, pod) in pods.clone().into_iter().enumerate() {
        kube.delete_gateway_pod(&pod)
            .await
            .unwrap_or_else(|err| panic!("delete gateway pod {pod}: {err}"));
        pods = kube.wait_for_gateway_pods(2).await.unwrap_or_else(|err| {
            panic!("gateway pods should recover after deleting {pod}: {err}")
        });
        assert_exec_through_all_pods(&kube, &pods, &sandbox.name, &format!("delete-{pod}"))
            .await
            .unwrap_or_else(|err| panic!("exec should work after deleting {pod}: {err}"));
        exec_through_configured_gateway(
            &sandbox.name,
            &format!("ha-rebalance-client-delete-{pod}"),
        )
        .await
        .unwrap_or_else(|err| {
            panic!(
                "exec should work through the configured client gateway endpoint after deleting {pod}: {err}"
            )
        });
        let mut delete_sandbox =
            create_sandbox_through_configured_gateway(&format!("delete-{idx}"))
                .await
                .unwrap_or_else(|err| {
                    panic!(
                        "sandbox create and readiness watch should succeed through the configured gateway endpoint after deleting {pod}: {err}"
                    )
                });
        delete_sandbox.cleanup().await;
    }

    sandbox.cleanup().await;
}

#[tokio::test]
async fn sandbox_file_sync_survives_gateway_pod_rolls() {
    let _test_lock = KUBE_HA_TEST_LOCK.lock().await;
    let kube = KubeTarget::from_env();

    kube.scale_gateway(2)
        .await
        .expect("gateway should run with two HA replicas for sync outage testing");
    kube.wait_for_gateway_pods(2)
        .await
        .expect("gateway should have two ready replicas before sync outage testing");

    let mut sandbox =
        SandboxGuard::create_keep(&["sh", "-c", "echo Ready && sleep infinity"], "Ready")
            .await
            .expect("sandbox create --keep for HA sync testing");

    let tmpdir = tempfile::tempdir().expect("create HA sync tmpdir");
    let upload_dir = tmpdir.path().join("ha-sync-upload");
    fs::create_dir_all(&upload_dir).expect("create HA sync upload dir");
    fs::write(upload_dir.join("marker.txt"), "ha-sync-marker").expect("write HA sync marker");

    let payload = upload_dir.join("payload.bin");
    write_deterministic_payload(&payload, HA_SYNC_PAYLOAD_BYTES);
    let expected_hash = sha256_file(&payload);

    let upload = upload_command(&sandbox.name, &upload_dir, "/sandbox/ha-sync");
    run_cli_during_gateway_pod_roll(&kube, upload, "upload")
        .await
        .expect("upload should survive rolling gateway pod outages");

    let remote_payload = "/sandbox/ha-sync/ha-sync-upload/payload.bin";
    let remote_hash_cmd = format!("sha256sum {remote_payload} | awk '{{print $1}}'");
    let remote_hash = sandbox
        .exec(&["sh", "-c", &remote_hash_cmd])
        .await
        .expect("uploaded payload should be readable in sandbox");
    assert!(
        strip_ansi(&remote_hash).contains(&expected_hash),
        "uploaded payload SHA-256 mismatch; expected {expected_hash}, got:\n{remote_hash}"
    );

    let download_dir = tmpdir.path().join("ha-sync-download");
    fs::create_dir_all(&download_dir).expect("create HA sync download dir");
    let download = download_command(
        &sandbox.name,
        "/sandbox/ha-sync/ha-sync-upload",
        &download_dir,
    );
    run_cli_during_gateway_pod_roll(&kube, download, "download")
        .await
        .expect("download should survive rolling gateway pod outages");

    let actual_hash = sha256_file(&download_dir.join("payload.bin"));
    assert_eq!(
        expected_hash, actual_hash,
        "downloaded payload SHA-256 mismatch after gateway pod rolls"
    );
    let marker = fs::read_to_string(download_dir.join("marker.txt"))
        .expect("read downloaded HA sync marker");
    assert_eq!(marker, "ha-sync-marker", "downloaded marker mismatch");

    sandbox.cleanup().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one rollout scenario, each step with its own deadline
async fn supervisor_sessions_redistribute_across_gateway_pod_rolls() {
    let _test_lock = KUBE_HA_TEST_LOCK.lock().await;
    let kube = KubeTarget::from_env();
    let deadline = Instant::now() + HA_REDISTRIBUTION_TEST_BUDGET;

    let scaled = within(
        deadline,
        HA_ROLLOUT_TIMEOUT,
        "scale gateway to two replicas",
        kube.scale_gateway(2),
    )
    .await;
    kube.check(
        "gateway should run two HA replicas before the rollout",
        scaled,
    )
    .await;
    let old_pods = kube
        .wait_for_gateway_pods_until(2, deadline.min(Instant::now() + HA_READY_PODS_TIMEOUT))
        .await;
    let old_pods = kube
        .check("two ready gateway replicas before the rollout", old_pods)
        .await;

    let created = within(
        deadline,
        HA_REDISTRIBUTION_CREATE_TIMEOUT,
        "create sandboxes through the configured gateway",
        try_join_all((0..HA_REDISTRIBUTION_SANDBOXES).map(|idx| async move {
            let phase = format!("redistribute-{idx}");
            create_sandbox_through_configured_gateway(&phase).await
        })),
    )
    .await;
    let mut sandboxes = kube
        .check("create sandboxes through the configured gateway", created)
        .await;
    let names: Vec<String> = sandboxes
        .iter()
        .map(|sandbox| sandbox.name.clone())
        .collect();

    let before = kube.wait_for_session_accounting(2, &names, deadline).await;
    let before = kube
        .check(
            "session gauges should account for every Ready sandbox before the rollout",
            before,
        )
        .await;
    eprintln!(
        "supervisor sessions before rollout: {:?} for {} Ready sandboxes",
        before.sessions_by_pod, before.ready_sandboxes
    );

    let observation = kube.restart_gateway_and_observe_drain(deadline).await;
    let observation = kube.check("gateway rollout restart", observation).await;
    eprintln!(
        "gateway pods terminating during rollout: {:?}; draining: {:?}; left after: {:?}",
        observation.terminating, observation.draining, observation.exit_times
    );
    assert!(
        !observation.draining.is_empty(),
        "expected {DRAINING_METRIC}=1 on a terminating gateway pod; terminating pods seen: {:?}",
        observation.terminating
    );
    assert!(
        observation
            .draining
            .iter()
            .all(|pod| old_pods.contains(pod)),
        "only replaced pods should drain; old={old_pods:?} draining={:?}",
        observation.draining
    );
    // The gauge flips before any session closes, so only the exit time tells
    // a finished drain from a kill at the end of the grace period.
    assert!(
        observation
            .exit_times
            .values()
            .all(|elapsed| *elapsed <= HA_DRAIN_EXIT_BOUND),
        "every terminating gateway pod should leave within {HA_DRAIN_EXIT_BOUND:?}; a longer stay means the drain overran its 25 s bound or the 30 s grace period cut it off; left after: {:?}",
        observation.exit_times
    );

    let new_pods = kube
        .wait_for_gateway_pods_until(2, deadline.min(Instant::now() + HA_READY_PODS_TIMEOUT))
        .await;
    let new_pods = kube
        .check("two ready gateway replicas after the rollout", new_pods)
        .await;
    assert!(
        new_pods.iter().all(|pod| !old_pods.contains(pod)),
        "rollout restart should replace every gateway pod; old={old_pods:?} new={new_pods:?}"
    );

    // Exec runs only after this settles: new execs fail with
    // FAILED_PRECONDITION while a moved sandbox reports Provisioning.
    let after = kube.wait_for_session_accounting(2, &names, deadline).await;
    let after = kube
        .check(
            "every sandbox should be Ready with exactly one supervisor session on the new pods",
            after,
        )
        .await;
    eprintln!(
        "supervisor sessions after rollout: {:?} for {} Ready sandboxes",
        after.sessions_by_pod, after.ready_sandboxes
    );

    let exec = within(
        deadline,
        HA_EXEC_TIMEOUT,
        "exec through every new gateway pod",
        async {
            for (idx, sandbox) in sandboxes.iter().enumerate() {
                let phase = format!("redistribute-{idx}");
                assert_exec_through_all_pods(&kube, &new_pods, &sandbox.name, &phase)
                    .await
                    .map_err(|err| {
                        format!(
                            "exec through every new gateway pod for {}: {err}",
                            sandbox.name
                        )
                    })?;
                let marker = format!("ha-redistribute-client-{idx}");
                exec_through_configured_gateway(&sandbox.name, &marker)
                    .await
                    .map_err(|err| {
                        format!(
                            "exec through the configured gateway for {}: {err}",
                            sandbox.name
                        )
                    })?;
            }
            Ok(())
        },
    )
    .await;
    kube.check("exec after the rollout", exec).await;

    for sandbox in &mut sandboxes {
        sandbox.cleanup().await;
    }
}

#[test]
fn prometheus_count_reads_unlabelled_samples_only() {
    let text = "# TYPE openshell_server_supervisor_sessions gauge\n\
                openshell_server_supervisor_sessions 3\n\
                openshell_server_supervisor_sessions_total 9\n\
                openshell_server_relay_rejected_total{reason=\"global_capacity\"} 1\n";
    assert_eq!(
        prometheus_count(text, "openshell_server_supervisor_sessions"),
        Ok(3)
    );
    assert!(prometheus_count(text, "openshell_server_relay_rejected_total").is_err());
    assert!(prometheus_count(text, "openshell_server_missing").is_err());
}

#[test]
fn terminating_pod_exit_time_runs_from_first_sighting_to_first_listing_without_it() {
    let start = Instant::now();
    let at = |secs| start + Duration::from_secs(secs);
    let mut first_seen = BTreeMap::new();
    let mut exit_times = BTreeMap::new();

    record_terminating_pods(&mut first_seen, &mut exit_times, &["old-a"], at(0), at(1));
    record_terminating_pods(
        &mut first_seen,
        &mut exit_times,
        &["old-a", "old-b"],
        at(2),
        at(3),
    );
    record_terminating_pods(&mut first_seen, &mut exit_times, &["old-b"], at(10), at(11));
    assert_eq!(
        exit_times,
        BTreeMap::from([("old-a".to_string(), Duration::from_secs(9))])
    );
    assert_eq!(first_seen, BTreeMap::from([("old-b".to_string(), at(3))]));

    record_terminating_pods(&mut first_seen, &mut exit_times, &[], at(40), at(41));
    assert_eq!(exit_times.get("old-b"), Some(&Duration::from_secs(37)));
    assert!(first_seen.is_empty());
}
