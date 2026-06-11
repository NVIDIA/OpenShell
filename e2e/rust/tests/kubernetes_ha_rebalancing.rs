// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

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

    async fn roll_gateway_pods(
        &self,
        pods: Vec<String>,
        expected: usize,
    ) -> Result<(), String> {
        for pod in pods {
            self.delete_gateway_pod(&pod).await?;
            self.wait_for_gateway_pods(expected).await?;
        }
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
    fs::write(upload_dir.join("marker.txt"), "ha-sync-marker")
        .expect("write HA sync marker");

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
