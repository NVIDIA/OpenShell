// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use std::process::Stdio;
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tokio::process::{Child, Command};

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

    async fn wait_for_gateway_pods(&self, expected: usize) -> Result<Vec<String>, String> {
        let deadline = Instant::now() + Duration::from_secs(240);
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
            "gateway pods did not reach expected ready count {expected} within 240s; last={last}"
        ))
    }

    async fn gateway_pods(&self) -> Result<Vec<GatewayPod>, String> {
        let selector = format!("app.kubernetes.io/instance={}", self.release);
        let json = self
            .kubectl(&[
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
            if !item["metadata"]["deletionTimestamp"].is_null() {
                continue;
            }
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
            pods.push(GatewayPod {
                name: name.to_string(),
                ready,
            });
        }
        pods.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(pods)
    }
}

#[derive(Debug)]
struct GatewayPod {
    name: String,
    ready: bool,
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
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} is not set; run through e2e/rust/e2e-kubernetes.sh")
    })
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

async fn create_sandbox_through_configured_gateway(
    phase: &str,
) -> Result<SandboxGuard, String> {
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

#[tokio::test]
async fn sandbox_exec_rebalances_across_gateway_scale_and_rollout() {
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
        pods = kube
            .wait_for_gateway_pods(2)
            .await
            .unwrap_or_else(|err| panic!("gateway pods should recover after deleting {pod}: {err}"));
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
