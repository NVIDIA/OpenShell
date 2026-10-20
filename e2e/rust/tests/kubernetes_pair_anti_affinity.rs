// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! Run with a gateway configured for required pair anti-affinity and at least
//! two eligible nodes. This test is opt-in because the default local cluster
//! has one node and the default gateway policy is off.

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::{Value, json};

async fn kubectl(args: &[&str]) -> Value {
    let mut cmd = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE") {
        cmd.arg("--context").arg(context);
    }
    let output = cmd.args(args).output().await.expect("spawn kubectl");
    assert!(
        output.status.success(),
        "kubectl {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("kubectl JSON")
}

async fn pair(name: &str) -> Vec<Value> {
    let namespace =
        std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let resources = kubectl(&[
        "-n",
        &namespace,
        "get",
        "sandboxes.agents.x-k8s.io",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
        "-o",
        "json",
    ])
    .await;
    let resources = resources["items"].as_array().expect("Sandbox list");
    assert_eq!(resources.len(), 1);
    let pair =
        resources[0]["spec"]["podTemplate"]["metadata"]["labels"]["openshell.ai/boundary-pair"]
            .as_str()
            .expect("pair label");
    let pods = kubectl(&[
        "-n",
        &namespace,
        "get",
        "pods",
        "-l",
        &format!("openshell.ai/boundary-pair={pair}"),
        "-o",
        "json",
    ])
    .await;
    let pods = pods["items"].as_array().expect("Pod list").clone();
    assert_eq!(pods.len(), 2);
    for pod in &pods {
        let role = pod["metadata"]["labels"]["openshell.ai/boundary-role"]
            .as_str()
            .expect("role");
        let peer = match role {
            "workload" => "supervisor",
            "supervisor" => "workload",
            other => panic!("unexpected role {other}"),
        };
        let expected = json!({
            "topologyKey": "kubernetes.io/hostname",
            "labelSelector": {"matchLabels": {
                "openshell.ai/boundary-pair": pair,
                "openshell.ai/boundary-role": peer,
            }},
        });
        let terms = pod["spec"]["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"].as_array().expect("required terms");
        assert!(terms.contains(&expected), "missing pair rule: {pod}");
        assert!(
            pod["spec"]["nodeName"]
                .as_str()
                .is_some_and(|node| !node.is_empty())
        );
    }
    assert_ne!(pods[0]["spec"]["nodeName"], pods[1]["spec"]["nodeName"]);
    pods
}

#[tokio::test]
#[ignore = "requires required pair anti-affinity and two eligible Kubernetes nodes"]
async fn required_pair_separation_survives_stop_start() {
    let mut first = SandboxGuard::create_keep_with_args(
        &["--from", "docker.io/library/ubuntu:24.04"],
        &["sh", "-c", "echo affinity-ready; exec sleep infinity"],
        "affinity-ready",
    )
    .await
    .expect("create first sandbox");
    let before = pair(&first.name).await;
    let mut second = SandboxGuard::create_keep_with_args(
        &["--from", "docker.io/library/ubuntu:24.04"],
        &["sh", "-c", "echo affinity-ready; exec sleep infinity"],
        "affinity-ready",
    )
    .await
    .expect("create second sandbox");
    pair(&second.name).await;
    for verb in ["stop", "start"] {
        let (output, code) = run_cli(&["sandbox", verb, &first.name]).await;
        assert_eq!(code, 0, "sandbox {verb}: {output}");
    }
    first
        .exec(&["true"])
        .await
        .expect("restarted sandbox is usable");
    let after = pair(&first.name).await;
    for pod in &after {
        assert!(
            before
                .iter()
                .all(|old| old["metadata"]["uid"] != pod["metadata"]["uid"])
        );
    }
    second.cleanup().await;
    first.cleanup().await;
}
