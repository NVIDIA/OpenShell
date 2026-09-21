// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-warm-pool")]

//! Requires ci/values-warm-pool-preparation.yaml. Exercises preparation and single-use allocation.
use openshell_e2e::harness::{binary::openshell_cmd, sandbox::SandboxGuard};
use serde_json::Value;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

async fn cli(args: &[&str]) -> String {
    let output = tokio::time::timeout(
        Duration::from_secs(300),
        openshell_cmd().args(args).output(),
    )
    .await
    .expect("CLI timed out")
    .expect("run CLI");
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

async fn inventory(resource: &str, selector: &str) -> Vec<Value> {
    let context =
        std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE").expect("Kubernetes e2e context");
    let namespace = std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").expect("sandbox namespace");
    let output = tokio::process::Command::new("kubectl")
        .args([
            "--context",
            &context,
            "-n",
            &namespace,
            "get",
            resource,
            "-l",
            selector,
            "-o",
            "json",
        ])
        .output()
        .await
        .expect("run kubectl");
    assert!(
        output.status.success(),
        "kubectl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice::<Value>(&output.stdout).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone()
}

#[tokio::test]
async fn prepares_unassigned_pairs_and_retires_them_when_template_is_deleted() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let name = format!("pool-{suffix}");
    cli(&[
        "sandbox",
        "template",
        "create",
        &name,
        "--ready-within",
        "1s",
        "--max-burst",
        "2",
        "--env",
        "WARM_POOL_ENV=prepared",
    ])
    .await;
    let template: Value = serde_json::from_str(
        &cli(&["sandbox", "template", "get", &name, "--output", "json"]).await,
    )
    .unwrap();
    let id = template["id"].as_str().expect("template ID");
    let selector = format!("openshell.ai/warm-pool={id}");
    let result = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let pairs = inventory("sandboxes.agents.x-k8s.io", &selector).await;
            if pairs.len() == 2
                && pairs.iter().all(|pair| {
                    pair["metadata"]["labels"]["openshell.ai/warm-pool-state"] == "ready"
                })
            {
                for pair in &pairs {
                    assert!(pair["metadata"]["annotations"]["openshell.ai/sandbox-id"].is_null());
                    assert!(pair["metadata"]["labels"]["openshell.ai/sandbox-id"].is_null());
                    let physical = pair["metadata"]["annotations"]["openshell.ai/warm-pair-id"]
                        .as_str()
                        .unwrap();
                    let pods =
                        inventory("pods", &format!("openshell.ai/boundary-pair={physical}")).await;
                    assert_eq!(pods.len(), 2, "each pair owns exactly two Pods");
                    for pod in &pods {
                        assert_eq!(
                            pod["metadata"]["labels"]["openshell.ai/template-name"],
                            name
                        );
                        assert_eq!(pod["metadata"]["labels"]["openshell.ai/template-id"], id);
                    }
                    let proxy = pods
                        .iter()
                        .find(|pod| {
                            pod["metadata"]["labels"]["openshell.ai/boundary-role"] == "supervisor"
                        })
                        .expect("proxy Pod");
                    assert!(
                        proxy["status"]["conditions"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .all(|c| c["type"] != "Ready" || c["status"] != "True"),
                        "idle proxy must not report activated readiness"
                    );
                }
                return;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await;
    if result.is_err() {
        let pairs = inventory("sandboxes.agents.x-k8s.io", &selector).await;
        let states: Vec<_> = pairs.iter().map(|pair| serde_json::json!({
            "name": pair["metadata"]["name"],
            "state": pair["metadata"]["labels"]["openshell.ai/warm-pool-state"],
            "last_registration": pair["metadata"]["annotations"]["openshell.ai/warm-proxy-registered-at-ms"],
        })).collect();
        eprintln!("Timed out with {} pool pairs: {states:?}", pairs.len());
    }
    if result.is_err() {
        cli(&["sandbox", "template", "delete", &name]).await;
        panic!("two idle pairs should become ready without a logical sandbox");
    }
    exercise_claimed_pair(&name, suffix, &selector).await;
}

#[allow(clippy::too_many_lines)] // One lifecycle scenario keeps the shared two-pair capacity sequential.
async fn exercise_claimed_pair(name: &str, suffix: u128, selector: &str) {
    let prepared = inventory("sandboxes.agents.x-k8s.io", selector).await;
    let before_pods = inventory("pods", "openshell.ai/boundary-pair").await;
    let logical_name = format!("claim-{suffix}");
    let mut sandbox = SandboxGuard::manage_existing(logical_name.clone());
    cli(&[
        "sandbox",
        "create",
        "--detach",
        "--name",
        &logical_name,
        "--template",
        name,
        "--",
        "sh",
        "-c",
        "echo \"$WARM_POOL_ENV\" > /sandbox/.warm-main; exec sleep infinity",
    ])
    .await;
    assert!(
        sandbox
            .exec(&["cat", "/sandbox/.warm-main"])
            .await
            .unwrap()
            .contains("prepared")
    );
    let assigned_selector = format!("openshell.ai/sandbox-name={logical_name}");
    let assigned = inventory("sandboxes.agents.x-k8s.io", &assigned_selector).await;
    assert_eq!(assigned.len(), 1);
    let assigned = &assigned[0];
    assert!(
        prepared
            .iter()
            .any(|p| p["metadata"]["uid"] == assigned["metadata"]["uid"]),
        "create must claim an existing parent"
    );
    assert!(assigned["metadata"]["labels"]["openshell.ai/warm-pool"].is_null());
    let physical = assigned["metadata"]["annotations"]["openshell.ai/warm-pair-id"]
        .as_str()
        .unwrap();
    let pod_selector = format!("openshell.ai/boundary-pair={physical}");
    let after_pods = inventory("pods", &pod_selector).await;
    assert_eq!(after_pods.len(), 2);
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            let labeled = inventory("pods", &assigned_selector).await;
            if labeled.len() == 2
                && labeled.iter().all(|pod| {
                    pod["metadata"]["labels"]["openshell.ai/sandbox-id"]
                        == assigned["metadata"]["labels"]["openshell.ai/sandbox-id"]
                        && after_pods
                            .iter()
                            .any(|prepared| prepared["metadata"]["uid"] == pod["metadata"]["uid"])
                })
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("both prepared Pods should acquire the logical sandbox labels");
    for pod in &after_pods {
        assert_eq!(
            pod["metadata"]["labels"]["openshell.ai/template-name"],
            name
        );
        assert_eq!(
            pod["metadata"]["labels"]["openshell.ai/template-id"],
            assigned["metadata"]["labels"]["openshell.ai/template-id"]
        );
        assert!(
            before_pods
                .iter()
                .any(|before| before["metadata"]["uid"] == pod["metadata"]["uid"]),
            "assignment must preserve both prepared Pods"
        );
    }
    sandbox
        .exec(&["sh", "-c", "echo warm-workspace > /sandbox/.warm-test"])
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            let spares = inventory("sandboxes.agents.x-k8s.io", selector).await;
            if spares.len() == 2
                && spares
                    .iter()
                    .all(|p| p["metadata"]["labels"]["openshell.ai/warm-pool-state"] == "ready")
            {
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("claim should replenish the spare pool");
    cli(&["sandbox", "template", "delete", name]).await;
    tokio::time::timeout(Duration::from_secs(120), async {
        while !inventory("sandboxes.agents.x-k8s.io", selector)
            .await
            .is_empty()
        {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("template deletion should retire spare inventory");
    assert_eq!(
        inventory("sandboxes.agents.x-k8s.io", &assigned_selector)
            .await
            .len(),
        1,
        "template deletion must preserve assigned pairs"
    );
    cli(&["sandbox", "stop", &logical_name]).await;
    cli(&["sandbox", "start", &logical_name]).await;
    assert!(
        sandbox
            .exec(&["cat", "/sandbox/.warm-test"])
            .await
            .unwrap()
            .contains("warm-workspace")
    );
    sandbox.cleanup().await;
    tokio::time::timeout(Duration::from_secs(120), async {
        while !inventory("sandboxes.agents.x-k8s.io", &assigned_selector)
            .await
            .is_empty()
            || !inventory("pods", &pod_selector).await.is_empty()
        {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    })
    .await
    .expect("deleting the logical sandbox must delete the pair");
    let mut cold = SandboxGuard::create(&[])
        .await
        .expect("cold fallback remains available");
    let cold_parent = inventory(
        "sandboxes.agents.x-k8s.io",
        &format!("openshell.ai/sandbox-name={}", cold.name),
    )
    .await;
    assert_eq!(cold_parent.len(), 1);
    assert!(cold_parent[0]["metadata"]["annotations"]["openshell.ai/warm-pair-id"].is_null());
    cold.cleanup().await;
}
