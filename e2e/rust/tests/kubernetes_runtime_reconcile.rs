// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

//! A stopped sandbox whose stored bootstrap image predates a gateway upgrade
//! starts with the gateway's configured runtime image and keeps its identity
//! and workspace.

use std::process::Stdio;

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::sandbox::SandboxGuard;

const BOOTSTRAP_CONTAINER: &str = "openshell-sandbox-bootstrap";
const STALE_IMAGE: &str = "registry.invalid/openshell/sandbox:stale";
const MARKER: &str = "openshell-runtime-reconcile";
const MARKER_PATH: &str = "/sandbox/.openshell-runtime-reconcile";

fn namespace() -> String {
    std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".to_string())
}

async fn kubectl(args: &[&str]) -> String {
    let mut cmd = tokio::process::Command::new("kubectl");
    if let Ok(context) = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        && !context.trim().is_empty()
    {
        cmd.arg("--context").arg(context);
    }
    let output = cmd
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .unwrap_or_else(|error| panic!("spawn kubectl {args:?}: {error}"));
    assert!(
        output.status.success(),
        "kubectl {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Return the sandbox's Agent Sandbox resource and the index of its stored
/// bootstrap init container.
async fn sandbox_resource(name: &str) -> (serde_json::Value, usize) {
    let output = kubectl(&[
        "-n",
        &namespace(),
        "get",
        "sandboxes.agents.x-k8s.io",
        "-l",
        &format!("openshell.ai/sandbox-name={name}"),
        "-o",
        "json",
    ])
    .await;
    let list: serde_json::Value = serde_json::from_str(&output).expect("parse Sandbox list");
    let [resource] = list["items"].as_array().expect("Sandbox items").as_slice() else {
        panic!("expected one Sandbox resource for {name}: {list}");
    };
    let index = resource["spec"]["podTemplate"]["spec"]["initContainers"]
        .as_array()
        .expect("stored init containers")
        .iter()
        .position(|container| container["name"] == BOOTSTRAP_CONTAINER)
        .expect("stored bootstrap init container");
    (resource.clone(), index)
}

fn bootstrap_image(resource: &serde_json::Value, index: usize) -> &serde_json::Value {
    &resource["spec"]["podTemplate"]["spec"]["initContainers"][index]["image"]
}

#[tokio::test]
async fn start_refreshes_stale_bootstrap_image() {
    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-c", "echo reconcile-ready; exec sleep infinity"],
        "reconcile-ready",
    )
    .await
    .expect("create sandbox");
    sandbox
        .exec(&[
            "sh",
            "-c",
            &format!("printf '%s\\n' '{MARKER}' > '{MARKER_PATH}'"),
        ])
        .await
        .expect("write workspace marker");
    let (output, code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(code, 0, "sandbox stop failed:\n{output}");

    // An older gateway stored its own runtime image in the resource.
    let (before, index) = sandbox_resource(&sandbox.name).await;
    let patch = serde_json::json!([{
        "op": "replace",
        "path": format!("/spec/podTemplate/spec/initContainers/{index}/image"),
        "value": STALE_IMAGE,
    }]);
    kubectl(&[
        "-n",
        &namespace(),
        "patch",
        "sandboxes.agents.x-k8s.io",
        before["metadata"]["name"]
            .as_str()
            .expect("Sandbox resource name"),
        "--type=json",
        "-p",
        &patch.to_string(),
    ])
    .await;

    let (output, code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(code, 0, "sandbox start failed:\n{output}");

    let marker = sandbox
        .exec(&["cat", MARKER_PATH])
        .await
        .expect("read workspace marker");
    assert!(
        marker.lines().any(|line| line.trim() == MARKER),
        "workspace marker should survive the restart:\n{marker}"
    );
    let (after, after_index) = sandbox_resource(&sandbox.name).await;
    assert_eq!(after["metadata"]["uid"], before["metadata"]["uid"]);
    assert_eq!(
        bootstrap_image(&after, after_index),
        bootstrap_image(&before, index)
    );

    sandbox.cleanup().await;
}
