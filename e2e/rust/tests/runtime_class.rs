// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! E2E test: verify `--runtime-class` propagates to the sandbox pod spec.
//!
//! Registers a `RuntimeClass` whose handler is `runc` (already present in
//! k3d/containerd) so the pod still schedules, runs `openshell sandbox create
//! --runtime-class <name>`, and asserts the resulting pod has
//! `spec.runtimeClassName` set to the requested value.

use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::binary::openshell_cmd;

const SANDBOX_NAMESPACE: &str = "openshell";
const RUNTIME_CLASS_NAME: &str = "openshell-e2e-runtime-class";

const RUNTIME_CLASS_MANIFEST: &str = r"apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: openshell-e2e-runtime-class
handler: runc
";

async fn kubectl(args: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new("kubectl")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("failed to run kubectl: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !output.status.success() {
        return Err(format!("kubectl {args:?} failed: {stdout}{stderr}"));
    }
    Ok(stdout)
}

async fn apply_runtime_class() -> Result<(), String> {
    let mut child = tokio::process::Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("failed to spawn kubectl apply: {e}"))?;
    {
        use tokio::io::AsyncWriteExt;
        let mut stdin = child.stdin.take().expect("stdin piped");
        stdin
            .write_all(RUNTIME_CLASS_MANIFEST.as_bytes())
            .await
            .map_err(|e| format!("write kubectl stdin: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("kubectl apply wait: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "kubectl apply -f - failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ));
    }
    Ok(())
}

async fn delete_runtime_class() {
    let _ = kubectl(&[
        "delete",
        "runtimeclass",
        RUNTIME_CLASS_NAME,
        "--ignore-not-found",
    ])
    .await;
}

async fn delete_sandbox(name: &str) {
    let _ = kubectl(&[
        "delete",
        "sandbox",
        name,
        "-n",
        SANDBOX_NAMESPACE,
        "--ignore-not-found",
    ])
    .await;
}

fn unique_sandbox_name() -> String {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("rtc-e2e-{suffix}")
}

async fn wait_for_pod(name: &str, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(found) = kubectl(&[
            "get",
            "pod",
            name,
            "-n",
            SANDBOX_NAMESPACE,
            "-o",
            "jsonpath={.metadata.name}",
        ])
        .await
            && !found.trim().is_empty()
        {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(format!(
        "pod {name} did not appear in namespace {SANDBOX_NAMESPACE} within {timeout:?}"
    ))
}

#[tokio::test]
async fn runtime_class_flag_propagates_to_pod_spec() {
    apply_runtime_class()
        .await
        .expect("register e2e RuntimeClass");

    let sandbox_name = unique_sandbox_name();

    let mut create_cmd = openshell_cmd();
    create_cmd
        .args([
            "sandbox",
            "create",
            "--name",
            &sandbox_name,
            "--runtime-class",
            RUNTIME_CLASS_NAME,
            "--",
            "echo",
            "runtime-class-ok",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let create_result = tokio::time::timeout(Duration::from_secs(180), create_cmd.output()).await;

    let wait_err = wait_for_pod(&sandbox_name, Duration::from_secs(60)).await;

    let runtime_class_observed = kubectl(&[
        "get",
        "pod",
        &sandbox_name,
        "-n",
        SANDBOX_NAMESPACE,
        "-o",
        "jsonpath={.spec.runtimeClassName}",
    ])
    .await;

    delete_sandbox(&sandbox_name).await;
    delete_runtime_class().await;

    let create_output = create_result
        .expect("sandbox create did not finish in 180s")
        .expect("sandbox create spawn failed");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&create_output.stdout),
        String::from_utf8_lossy(&create_output.stderr),
    );
    assert!(
        create_output.status.success(),
        "sandbox create with --runtime-class failed:\n{combined}",
    );

    wait_err.expect("sandbox pod never appeared");

    let observed = runtime_class_observed.expect("read pod runtimeClassName");
    assert_eq!(
        observed.trim(),
        RUNTIME_CLASS_NAME,
        "pod {sandbox_name} should have spec.runtimeClassName={RUNTIME_CLASS_NAME}, got '{observed}'",
    );
}
