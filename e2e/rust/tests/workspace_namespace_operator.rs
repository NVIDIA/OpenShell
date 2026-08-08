// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-workspace-operator")]

//! E2E tests for operator workspace mode.
//!
//! The gateway is deployed with `workspace_mode = "operator"` and
//! `operator_namespace_label = "openshell.ai/e2e-operator-workspace=true"`.
//! Namespaces must be pre-provisioned and labeled before sandbox creation.
//! The gateway discovers valid namespaces via the label selector.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::output::strip_ansi;

const OPERATOR_LABEL: &str = "openshell.ai/e2e-operator-workspace=true";
const SA_NAME: &str = "openshell-sandbox";

fn kube_context() -> String {
    std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE")
        .expect("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE must be set")
}

async fn kubectl(args: &[&str]) -> (bool, String) {
    let context = kube_context();
    let output = tokio::process::Command::new("kubectl")
        .arg("--context")
        .arg(&context)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to spawn kubectl");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.success(), combined)
}

async fn run_cli(args: &[&str]) -> (bool, String) {
    let mut cmd = openshell_cmd();
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    let output = cmd.output().await.expect("failed to spawn openshell");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.success(), strip_ansi(&combined))
}

fn unique_namespace(prefix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        % 100_000;
    format!("{prefix}-{ts}")
}

async fn provision_operator_namespace(name: &str) {
    let (ok, out) = kubectl(&["create", "namespace", name]).await;
    assert!(ok, "failed to create namespace {name}: {out}");

    let (ok, out) = kubectl(&["label", "namespace", name, OPERATOR_LABEL]).await;
    assert!(ok, "failed to label namespace {name}: {out}");

    let (ok, out) = kubectl(&["create", "serviceaccount", SA_NAME, "-n", name]).await;
    assert!(ok, "failed to create SA in {name}: {out}");
}

async fn delete_namespace(name: &str) {
    let _ = kubectl(&[
        "delete",
        "namespace",
        name,
        "--ignore-not-found",
        "--wait=false",
    ])
    .await;
}

struct OperatorCleanup {
    workspace: String,
    namespace: String,
    sandboxes: Vec<String>,
}

impl Drop for OperatorCleanup {
    fn drop(&mut self) {
        let bin = openshell_bin();
        for sb in &self.sandboxes {
            let _ = std::process::Command::new(&bin)
                .args(["sandbox", "delete", sb, "--workspace", &self.workspace])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = std::process::Command::new(&bin)
            .args(["workspace", "delete", &self.workspace])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT_ACTIVE").unwrap_or_default();
        if !context.is_empty() {
            let _ = std::process::Command::new("kubectl")
                .args([
                    "--context",
                    &context,
                    "delete",
                    "namespace",
                    &self.namespace,
                    "--ignore-not-found",
                    "--wait=false",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

#[tokio::test]
async fn operator_sandbox_in_labeled_namespace() {
    let ns = unique_namespace("op");
    let _cleanup = OperatorCleanup {
        workspace: ns.clone(),
        namespace: ns.clone(),
        sandboxes: vec!["op-sb".into()],
    };

    // Pre-provision the namespace with the operator label and ServiceAccount.
    provision_operator_namespace(&ns).await;

    // Create a workspace matching the namespace name (operator mode: 1:1 mapping).
    let (ok, out) = run_cli(&["workspace", "create", "--name", &ns]).await;
    assert!(ok, "workspace create failed: {out}");

    // Poll until the gateway's namespace watcher discovers the labeled namespace
    // and sandbox creation succeeds (up to 30s).
    let mut sandbox_out = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, out) = run_cli(&[
            "sandbox",
            "create",
            "--workspace",
            &ns,
            "--name",
            "op-sb",
            "--",
            "echo",
            "operator-ok",
        ])
        .await;
        if ok {
            sandbox_out = out;
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("sandbox create did not succeed within 30s: {out}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(
        sandbox_out.contains("operator-ok"),
        "sandbox output missing expected string: {sandbox_out}"
    );

    // Verify the sandbox CR lives in the pre-provisioned namespace.
    let (ok, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", "-n", &ns, "-o", "name"]).await;
    assert!(ok, "sandbox CR should exist in namespace {ns}: {out}");
    assert!(
        out.contains("op-sb"),
        "sandbox CR name should be bare 'op-sb', got: {out}"
    );

    // Clean up.
    let (ok, out) = run_cli(&["sandbox", "delete", "op-sb", "--workspace", &ns]).await;
    assert!(ok, "sandbox delete failed: {out}");

    let (ok, out) = run_cli(&["workspace", "delete", &ns]).await;
    assert!(ok, "workspace delete failed: {out}");

    delete_namespace(&ns).await;
}

#[tokio::test]
async fn operator_rejects_unlabeled_namespace() {
    let ns = unique_namespace("opun");
    let _cleanup = OperatorCleanup {
        workspace: ns.clone(),
        namespace: ns.clone(),
        sandboxes: vec![],
    };

    // Create namespace WITHOUT the operator label.
    let (ok, out) = kubectl(&["create", "namespace", &ns]).await;
    assert!(ok, "failed to create namespace: {out}");

    // Create the ServiceAccount (not the label — that's the point).
    let (ok, _) = kubectl(&["create", "serviceaccount", SA_NAME, "-n", &ns]).await;
    assert!(ok, "failed to create SA");

    // Create workspace.
    let (ok, out) = run_cli(&["workspace", "create", "--name", &ns]).await;
    assert!(ok, "workspace create failed: {out}");

    // Attempt sandbox creation — should fail because namespace is not in the allowlist.
    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ns,
        "--name",
        "should-fail",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(
        !ok,
        "sandbox create should fail for unlabeled namespace, but succeeded: {out}"
    );

    // Clean up.
    let _ = run_cli(&["workspace", "delete", &ns]).await;
    delete_namespace(&ns).await;
}

#[tokio::test]
async fn operator_rejects_nonexistent_namespace() {
    let ns = unique_namespace("opne");
    let _cleanup = OperatorCleanup {
        workspace: ns.clone(),
        namespace: ns.clone(),
        sandboxes: vec![],
    };

    // Create workspace with no matching namespace at all.
    let (ok, out) = run_cli(&["workspace", "create", "--name", &ns]).await;
    assert!(ok, "workspace create failed: {out}");

    // Attempt sandbox creation — should fail.
    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ns,
        "--name",
        "should-fail",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(
        !ok,
        "sandbox create should fail for nonexistent namespace, but succeeded: {out}"
    );

    // Clean up.
    let _ = run_cli(&["workspace", "delete", &ns]).await;
}
