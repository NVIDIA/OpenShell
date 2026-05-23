// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Kubernetes SPIFFE e2e test.
//!
//! This test is intentionally opt-in through `OPENSHELL_E2E_KUBE_SPIFFE=1`.
//! It verifies that a sandbox pod is configured for SPIFFE JWT-SVID supervisor
//! authentication and that the supervisor actually takes the SPIFFE token path
//! instead of the Kubernetes ServiceAccount bootstrap path.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tokio::process::Command;

async fn kubectl(args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT")
        && !context.trim().is_empty()
    {
        cmd.arg("--context").arg(context);
    }
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
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

async fn kubectl_json(args: &[&str]) -> Result<Value, String> {
    let output = kubectl(args).await?;
    serde_json::from_str(&output)
        .map_err(|e| format!("failed to parse kubectl JSON output: {e}\n{output}"))
}

async fn wait_for_pod_json(namespace: &str, name: &str) -> Result<Value, String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut last_error = String::new();
    while tokio::time::Instant::now() < deadline {
        match kubectl_json(&["get", "pod", name, "-n", namespace, "-o", "json"]).await {
            Ok(pod) => return Ok(pod),
            Err(err) => last_error = err,
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(format!(
        "sandbox pod {name} did not appear within 120s; last error: {last_error}"
    ))
}

fn container<'a>(pod: &'a Value, name: &str) -> &'a Value {
    pod.pointer("/spec/containers")
        .and_then(Value::as_array)
        .and_then(|containers| {
            containers
                .iter()
                .find(|container| container["name"].as_str() == Some(name))
        })
        .unwrap_or_else(|| panic!("pod spec did not contain container {name}: {pod:#}"))
}

fn env_value<'a>(container: &'a Value, name: &str) -> Option<&'a str> {
    container
        .get("env")
        .and_then(Value::as_array)
        .and_then(|env| {
            env.iter()
                .find(|entry| entry["name"].as_str() == Some(name))
        })
        .and_then(|entry| entry["value"].as_str())
}

#[tokio::test]
async fn sandbox_uses_spiffe_jwt_svid_authentication() {
    if std::env::var("OPENSHELL_E2E_KUBE_SPIFFE").as_deref() != Ok("1") {
        eprintln!("Skipping Kubernetes SPIFFE e2e: OPENSHELL_E2E_KUBE_SPIFFE is not set");
        return;
    }

    let namespace =
        std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE").unwrap_or_else(|_| "openshell".to_string());

    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-c", "echo spiffe-ready && sleep infinity"],
        "spiffe-ready",
    )
    .await
    .expect("SPIFFE sandbox should become ready");

    let pod = wait_for_pod_json(&namespace, &sandbox.name)
        .await
        .expect("sandbox pod should exist");

    let spiffe_id = pod
        .pointer("/metadata/annotations/openshell.io~1spiffe-id")
        .and_then(Value::as_str)
        .expect("sandbox pod should carry openshell.io/spiffe-id annotation");
    let sandbox_id = pod
        .pointer("/metadata/labels/openshell.ai~1sandbox-id")
        .and_then(Value::as_str)
        .expect("sandbox pod should carry openshell.ai/sandbox-id label");
    assert!(
        spiffe_id.starts_with("spiffe://openshell.local/openshell/sandbox/"),
        "unexpected SPIFFE ID annotation: {spiffe_id}"
    );
    assert!(
        spiffe_id.ends_with(sandbox_id),
        "SPIFFE ID {spiffe_id} should be bound to sandbox id label {sandbox_id}"
    );

    let volumes = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .expect("sandbox pod should have volumes");
    assert!(
        volumes.iter().any(|volume| {
            volume["name"].as_str() == Some("spiffe-workload-api")
                && volume.pointer("/csi/driver").and_then(Value::as_str) == Some("csi.spiffe.io")
        }),
        "sandbox pod should mount the SPIFFE Workload API CSI volume: {volumes:#?}"
    );
    assert!(
        !volumes
            .iter()
            .any(|volume| volume["name"].as_str() == Some("openshell-sa-token")),
        "SPIFFE mode must not mount the Kubernetes ServiceAccount bootstrap token volume"
    );

    let agent = container(&pod, "agent");
    assert_eq!(
        env_value(agent, "OPENSHELL_SPIFFE_WORKLOAD_API_SOCKET"),
        Some("/spiffe-workload-api/spire-agent.sock")
    );
    assert_eq!(
        env_value(agent, "OPENSHELL_SPIFFE_AUDIENCE"),
        Some("openshell-gateway")
    );
    assert_eq!(env_value(agent, "OPENSHELL_SPIFFE_ID"), Some(spiffe_id));
    assert!(
        env_value(agent, "OPENSHELL_K8S_SA_TOKEN_FILE").is_none(),
        "SPIFFE mode must not configure the ServiceAccount bootstrap token env var"
    );

    let pod_ref = format!("pod/{}", sandbox.name);
    let logs = kubectl(&["logs", &pod_ref, "-n", &namespace, "-c", "agent", "--tail=300"])
        .await
        .expect("failed to fetch sandbox supervisor logs");
    assert!(
        logs.contains("fetching SPIFFE JWT-SVID for sandbox gateway authentication"),
        "supervisor logs should show SPIFFE JWT-SVID acquisition:\n{logs}"
    );
    assert!(
        !logs.contains("exchanging K8s ServiceAccount token for sandbox JWT"),
        "supervisor logs should not show ServiceAccount bootstrap fallback:\n{logs}"
    );

    sandbox.cleanup().await;
}
