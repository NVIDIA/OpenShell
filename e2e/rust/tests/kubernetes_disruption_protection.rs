// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{SecondsFormat, Utc};
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const PROTECTED_UNTIL_ANNOTATION: &str = "openshell.io/disruption-protected-until";

#[tokio::test]
async fn sandbox_disruption_protection_denies_eviction_and_expires() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        % 1_000_000;
    let sandbox_name = format!("pdb-e2e-{suffix}");
    let driver_config = r#"{"kubernetes":{"disruption_protection":{"duration":"30m"}}}"#;
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &[
            "--name",
            &sandbox_name,
            "--driver-config-json",
            driver_config,
        ],
        &["sh", "-lc", "echo pdb-ready; sleep infinity"],
        "pdb-ready",
    )
    .await
    .expect("create disruption-protected Kubernetes sandbox");

    let sandbox_object = wait_for_sandbox_object(&sandbox_name).await;
    let kube_name = sandbox_object["metadata"]["name"]
        .as_str()
        .expect("Sandbox metadata.name")
        .to_string();
    let sandbox_uid = sandbox_object["metadata"]["uid"]
        .as_str()
        .expect("Sandbox metadata.uid");
    let sandbox_resource_id = sandbox_object["metadata"]["annotations"]["openshell.ai/sandbox-id"]
        .as_str()
        .expect("Sandbox sandbox-id annotation");
    let pdb = wait_for_effective_pdb(&kube_name).await;
    let pod = wait_for_protected_pod(&pdb, sandbox_resource_id).await;
    let pod_name = pod["metadata"]["name"]
        .as_str()
        .expect("protected Pod metadata.name");

    assert_eq!(pdb["spec"]["minAvailable"], 1);
    assert_eq!(pdb["spec"]["unhealthyPodEvictionPolicy"], "AlwaysAllow");
    assert_eq!(pdb["metadata"]["ownerReferences"][0]["uid"], sandbox_uid);
    let protected_until = pdb["metadata"]["annotations"][PROTECTED_UNTIL_ANNOTATION]
        .as_str()
        .expect("PDB absolute protection deadline");
    assert_eq!(
        sandbox_object["metadata"]["annotations"][PROTECTED_UNTIL_ANNOTATION], protected_until,
        "Sandbox and PDB must persist the same absolute deadline"
    );
    assert!(protected_until.ends_with('Z'));
    assert_selector_matches_pod(&pdb, &pod);

    let eviction = evict_pod(pod_name).await;
    let eviction_error = format!(
        "{}{}",
        String::from_utf8_lossy(&eviction.stdout),
        String::from_utf8_lossy(&eviction.stderr)
    );
    assert!(
        !eviction.status.success(),
        "Eviction unexpectedly succeeded despite the PDB: {eviction_error}"
    );
    assert!(
        eviction_error.contains("TooManyRequests") && eviction_error.contains("disruption budget"),
        "Eviction failed for an unexpected reason: {eviction_error}"
    );

    let expiring_soon =
        (Utc::now() + chrono::Duration::seconds(15)).to_rfc3339_opts(SecondsFormat::Millis, true);
    // Update the authoritative Sandbox first. The future deadline gives its
    // watch event time to arm before the PDB annotation is synchronized.
    patch_deadline("sandboxes.agents.x-k8s.io", &kube_name, &expiring_soon).await;
    patch_deadline("poddisruptionbudget", &kube_name, &expiring_soon).await;
    wait_for_pdb_deletion(&kube_name).await;
    assert!(
        kubectl(&["get", "sandboxes.agents.x-k8s.io", &kube_name])
            .await
            .status
            .success(),
        "deadline cleanup must remove only the PDB, not the Sandbox"
    );

    sandbox.cleanup().await;
}

async fn wait_for_sandbox_object(sandbox_name: &str) -> Value {
    let selector = format!("openshell.ai/sandbox-name={sandbox_name}");
    for _ in 0..30 {
        let output = kubectl(&[
            "get",
            "sandboxes.agents.x-k8s.io",
            "--selector",
            &selector,
            "--output",
            "json",
        ])
        .await;
        if output.status.success() {
            let list: Value = serde_json::from_slice(&output.stdout).expect("parse Sandbox list");
            if let Some(object) = list["items"].as_array().and_then(|items| items.first()) {
                return object.clone();
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("Sandbox object for {sandbox_name} did not appear");
}

async fn wait_for_pdb(name: &str) -> Value {
    for _ in 0..30 {
        let output = kubectl(&["get", "poddisruptionbudget", name, "--output", "json"]).await;
        if output.status.success() {
            return serde_json::from_slice(&output.stdout).expect("parse PodDisruptionBudget");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("PodDisruptionBudget {name} did not appear");
}

async fn wait_for_effective_pdb(name: &str) -> Value {
    for _ in 0..60 {
        let pdb = wait_for_pdb(name).await;
        if pdb["status"]["expectedPods"] == 1
            && pdb["status"]["currentHealthy"] == 1
            && pdb["status"]["disruptionsAllowed"] == 0
        {
            return pdb;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("PodDisruptionBudget {name} never became effective");
}

async fn wait_for_protected_pod(pdb: &Value, sandbox_id: &str) -> Value {
    let selector_labels = pdb["spec"]["selector"]["matchLabels"]
        .as_object()
        .expect("PDB spec.selector.matchLabels");
    let selector = selector_labels
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}",
                value.as_str().expect("PDB selector label value")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(
        selector_labels
            .get("openshell.ai/sandbox-id")
            .and_then(Value::as_str),
        Some(sandbox_id),
        "PDB selector must target the requested sandbox ID"
    );
    for _ in 0..30 {
        let output = kubectl(&["get", "pods", "--selector", &selector, "--output", "json"]).await;
        if output.status.success() {
            let list: Value = serde_json::from_slice(&output.stdout).expect("parse Pod list");
            if let Some(pod) = list["items"].as_array().and_then(|items| items.first()) {
                return pod.clone();
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("protected Pod for sandbox {sandbox_id} did not appear");
}

fn assert_selector_matches_pod(pdb: &Value, pod: &Value) {
    let selector = pdb["spec"]["selector"]["matchLabels"]
        .as_object()
        .expect("PDB spec.selector.matchLabels");
    let pod_labels = pod["metadata"]["labels"]
        .as_object()
        .expect("Pod metadata.labels");
    for (key, expected) in selector {
        assert_eq!(
            pod_labels.get(key),
            Some(expected),
            "PDB selector label {key} does not match the protected Pod"
        );
    }
}

async fn evict_pod(pod_name: &str) -> std::process::Output {
    let namespace = sandbox_namespace();
    let endpoint = format!("/api/v1/namespaces/{namespace}/pods/{pod_name}/eviction");
    let eviction = serde_json::json!({
        "apiVersion": "policy/v1",
        "kind": "Eviction",
        "metadata": {
            "name": pod_name,
            "namespace": namespace,
        }
    });
    kubectl_with_stdin(
        &["create", "--raw", &endpoint, "--filename", "-"],
        &eviction.to_string(),
    )
    .await
}

async fn patch_deadline(resource: &str, name: &str, deadline: &str) {
    let patch = serde_json::json!({
        "metadata": {
            "annotations": {
                PROTECTED_UNTIL_ANNOTATION: deadline,
            }
        }
    })
    .to_string();
    let output = kubectl(&[
        "patch", resource, name, "--type", "merge", "--patch", &patch,
    ])
    .await;
    assert!(
        output.status.success(),
        "failed to patch {resource} {name}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wait_for_pdb_deletion(name: &str) {
    let mut last_error = String::new();
    for _ in 0..45 {
        let output = kubectl(&[
            "get",
            "poddisruptionbudget",
            name,
            "--ignore-not-found",
            "--output",
            "name",
        ])
        .await;
        if output.status.success() && output.stdout.iter().all(u8::is_ascii_whitespace) {
            return;
        }
        if !output.status.success() {
            last_error = String::from_utf8_lossy(&output.stderr).into_owned();
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("PodDisruptionBudget {name} was not deleted; last kubectl error: {last_error}");
}

async fn kubectl(args: &[&str]) -> std::process::Output {
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .expect("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE must be set");
    let namespace = sandbox_namespace();
    Command::new("kubectl")
        .args(["--context", &context, "--namespace", &namespace])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run kubectl")
}

async fn kubectl_with_stdin(args: &[&str], input: &str) -> std::process::Output {
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .expect("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE must be set");
    let namespace = sandbox_namespace();
    let mut child = Command::new("kubectl")
        .args(["--context", &context, "--namespace", &namespace])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kubectl");
    child
        .stdin
        .take()
        .expect("kubectl stdin")
        .write_all(input.as_bytes())
        .await
        .expect("write kubectl stdin");
    child.wait_with_output().await.expect("run kubectl")
}

fn sandbox_namespace() -> String {
    std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
        .expect("OPENSHELL_E2E_SANDBOX_NAMESPACE must be set")
}
