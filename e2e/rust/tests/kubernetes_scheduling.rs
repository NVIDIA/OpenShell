// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Run via e2e:kubernetes:scheduling with a shared-supervisor fixture. The same
//! test covers one eligible node, required separation, and three node pools.

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;

async fn kubectl(args: &[&str]) -> Value {
    let mut command = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        command.arg("--context").arg(context);
    }
    let output = command.args(args).output().await.expect("spawn kubectl");
    assert!(
        output.status.success(),
        "kubectl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("kubectl JSON")
}

async fn assert_pool(node: &str, role: &str) {
    let node = kubectl(&["get", "node", node, "-o", "json"]).await;
    assert_eq!(node["metadata"]["labels"]["openshell.ai/node-pool"], role);
}

async fn assert_placement(name: &str) -> Value {
    let mode =
        std::env::var("OPENSHELL_E2E_SCHEDULING_MODE").unwrap_or_else(|_| "preferred".into());
    let pools = std::env::var("OPENSHELL_E2E_SCHEDULING_POOLS").is_ok_and(|value| value == "1");
    let resources = kubectl(&[
        "get",
        "sandboxes.agents.x-k8s.io",
        "-A",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
        "-o",
        "json",
    ])
    .await;
    let resources = resources["items"].as_array().unwrap();
    assert_eq!(resources.len(), 1);
    let namespace = resources[0]["metadata"]["namespace"].as_str().unwrap();
    let pod_name = resources[0]["metadata"]["name"].as_str().unwrap();
    let workload = kubectl(&["get", "pod", pod_name, "-n", namespace, "-o", "json"]).await;
    assert_eq!(
        workload["metadata"]["labels"]["openshell.ai/runtime-role"],
        "workload"
    );
    let namespace =
        std::env::var("OPENSHELL_E2E_KUBE_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let infrastructure = kubectl(&[
        "get",
        "pods",
        "-n",
        &namespace,
        "-l",
        "openshell.ai/runtime-role",
        "-o",
        "json",
    ])
    .await;
    let key = if mode == "required" {
        "requiredDuringSchedulingIgnoredDuringExecution"
    } else {
        "preferredDuringSchedulingIgnoredDuringExecution"
    };
    if mode != "off" {
        let rule = &workload["spec"]["affinity"]["podAntiAffinity"][key][0];
        let term = if mode == "preferred" {
            &rule["podAffinityTerm"]
        } else {
            rule
        };
        assert_eq!(
            term["labelSelector"]["matchLabels"]["openshell.ai/runtime-role"],
            "supervisor"
        );
        assert_eq!(term["namespaceSelector"], serde_json::json!({}));
    }
    let mut found_supervisor = false;
    let mut gateway_node = None;
    for pod in infrastructure["items"].as_array().unwrap() {
        if !pod["metadata"]["deletionTimestamp"].is_null() {
            continue;
        }
        let role = pod["metadata"]["labels"]["openshell.ai/runtime-role"]
            .as_str()
            .unwrap();
        let node = pod["spec"]["nodeName"]
            .as_str()
            .expect("infrastructure scheduled");
        if role == "supervisor" {
            found_supervisor = true;
            if mode == "required" {
                assert_ne!(pod["spec"]["nodeName"], workload["spec"]["nodeName"]);
            }
            if mode != "off" {
                assert!(pod["spec"]["affinity"]["podAntiAffinity"][key].is_array());
            }
        }
        if role == "gateway" {
            gateway_node = Some(node.to_string());
        }
        if pools {
            let node = kubectl(&["get", "node", node, "-o", "json"]).await;
            assert_eq!(node["metadata"]["labels"]["openshell.ai/node-pool"], role);
        }
    }
    assert!(
        found_supervisor,
        "shared supervisor must carry the stable role label"
    );
    assert!(
        gateway_node.is_some(),
        "gateway must carry the stable role label"
    );
    if pools {
        assert_pool(workload["spec"]["nodeName"].as_str().unwrap(), "workload").await;
    }
    workload
}

#[tokio::test]
async fn role_placement_survives_workload_restart() {
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &["--from", "docker.io/library/ubuntu:24.04"],
        &["sh", "-c", "echo scheduling-ready; exec sleep infinity"],
        "scheduling-ready",
    )
    .await
    .expect("create scheduled sandbox");
    let before = assert_placement(&sandbox.name).await;
    for verb in ["stop", "start"] {
        let (output, code) = run_cli(&["sandbox", verb, &sandbox.name]).await;
        assert_eq!(code, 0, "{verb}: {output}");
    }
    sandbox
        .exec(&["true"])
        .await
        .expect("restarted sandbox usable");
    let after = assert_placement(&sandbox.name).await;
    assert_ne!(before["metadata"]["uid"], after["metadata"]["uid"]);
    sandbox.cleanup().await;
}
