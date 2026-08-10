// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use std::process::Stdio;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tokio::process::Command;

const PROTECTED_UNTIL_ANNOTATION: &str = "openshell.io/disruption-protected-until";

#[tokio::test]
async fn sandbox_disruption_protection_creates_and_cleans_up_pdb() {
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
    let pdb = wait_for_pdb(&kube_name).await;

    assert_eq!(pdb["spec"]["minAvailable"], 1);
    assert_eq!(pdb["spec"]["unhealthyPodEvictionPolicy"], "AlwaysAllow");
    assert_eq!(pdb["metadata"]["ownerReferences"][0]["uid"], sandbox_uid);
    assert!(
        pdb["metadata"]["annotations"][PROTECTED_UNTIL_ANNOTATION]
            .as_str()
            .is_some_and(|deadline| deadline.ends_with('Z')),
        "PDB must persist an absolute UTC deadline: {pdb}"
    );

    sandbox.cleanup().await;
    wait_for_pdb_deletion(&kube_name).await;
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

async fn wait_for_pdb_deletion(name: &str) {
    for _ in 0..30 {
        let output = kubectl(&["get", "poddisruptionbudget", name]).await;
        if !output.status.success() {
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    panic!("PodDisruptionBudget {name} was not deleted");
}

async fn kubectl(args: &[&str]) -> std::process::Output {
    let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .expect("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE must be set");
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE")
        .expect("OPENSHELL_E2E_SANDBOX_NAMESPACE must be set");
    Command::new("kubectl")
        .args(["--context", &context, "--namespace", &namespace])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run kubectl")
}
