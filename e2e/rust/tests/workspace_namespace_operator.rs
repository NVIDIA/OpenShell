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
const DURABLE_MAIN_SCRIPT: &str = r#"echo "$1"; exec sleep infinity"#;

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

async fn wait_sandbox_gone(workspace: &str, sandbox: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, out) = run_cli(&["sandbox", "list", "--workspace", workspace]).await;
        if ok && !out.contains(sandbox) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "sandbox {sandbox} still listed in workspace {workspace} 30s after delete: {out}"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
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
            "sh",
            "-c",
            DURABLE_MAIN_SCRIPT,
            "_",
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

    // Verify sandbox is resolvable through the OpenShell control plane.
    let (ok, out) = run_cli(&["sandbox", "list", "--workspace", &ns]).await;
    assert!(ok, "sandbox list failed: {out}");
    assert!(
        out.contains("op-sb"),
        "sandbox list should find op-sb via control plane: {out}"
    );

    let (ok, out) = run_cli(&["sandbox", "get", "op-sb", "--workspace", &ns]).await;
    assert!(ok, "sandbox get failed: {out}");
    assert!(
        out.contains("op-sb"),
        "sandbox get should resolve op-sb via control plane: {out}"
    );

    // Verify sandbox delete works through the control plane.
    let (ok, out) = run_cli(&["sandbox", "delete", "op-sb", "--workspace", &ns]).await;
    assert!(ok, "sandbox delete failed: {out}");

    // Wait for the sandbox CR to be fully removed (deletion is asynchronous).
    wait_sandbox_gone(&ns, "op-sb").await;

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
        "sh",
        "-c",
        DURABLE_MAIN_SCRIPT,
        "_",
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
        "sh",
        "-c",
        DURABLE_MAIN_SCRIPT,
        "_",
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

#[tokio::test]
async fn operator_workspace_delete_preserves_namespace() {
    let ns = unique_namespace("opdel");
    let _cleanup = OperatorCleanup {
        workspace: ns.clone(),
        namespace: ns.clone(),
        sandboxes: vec!["opdel-sb".into()],
    };

    provision_operator_namespace(&ns).await;

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ns]).await;
    assert!(ok, "workspace create failed: {out}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, out) = run_cli(&[
            "sandbox",
            "create",
            "--workspace",
            &ns,
            "--name",
            "opdel-sb",
            "--",
            "sh",
            "-c",
            DURABLE_MAIN_SCRIPT,
            "_",
            "opdel-ok",
        ])
        .await;
        if ok {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("sandbox create did not succeed within 30s: {out}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let (ok, out) = run_cli(&["sandbox", "delete", "opdel-sb", "--workspace", &ns]).await;
    assert!(ok, "sandbox delete failed: {out}");

    wait_sandbox_gone(&ns, "opdel-sb").await;

    let (ok, out) = run_cli(&["workspace", "delete", &ns]).await;
    assert!(ok, "workspace delete failed: {out}");

    let (ok, out) = kubectl(&["get", "namespace", &ns]).await;
    assert!(
        ok,
        "operator namespace {ns} should still exist after workspace delete: {out}"
    );

    let (ok, label_out) =
        kubectl(&["get", "namespace", &ns, "-o", "jsonpath={.metadata.labels}"]).await;
    assert!(ok, "failed to read namespace labels: {label_out}");
    assert!(
        label_out.contains("openshell.ai/e2e-operator-workspace"),
        "operator label should be intact after workspace delete: {label_out}"
    );

    delete_namespace(&ns).await;
}

#[tokio::test]
async fn operator_label_removal_blocks_sandbox_creation() {
    let ns = unique_namespace("oplbl");
    let _cleanup = OperatorCleanup {
        workspace: ns.clone(),
        namespace: ns.clone(),
        sandboxes: vec!["lbl-sb1".into()],
    };

    provision_operator_namespace(&ns).await;

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ns]).await;
    assert!(ok, "workspace create failed: {out}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, out) = run_cli(&[
            "sandbox",
            "create",
            "--workspace",
            &ns,
            "--name",
            "lbl-sb1",
            "--",
            "sh",
            "-c",
            DURABLE_MAIN_SCRIPT,
            "_",
            "lbl-ok",
        ])
        .await;
        if ok {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("sandbox create did not succeed within 30s: {out}");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    let (ok, out) = run_cli(&["sandbox", "delete", "lbl-sb1", "--workspace", &ns]).await;
    assert!(ok, "sandbox lbl-sb1 delete failed: {out}");

    wait_sandbox_gone(&ns, "lbl-sb1").await;

    let (ok, out) = kubectl(&[
        "label",
        "namespace",
        &ns,
        "openshell.ai/e2e-operator-workspace-",
    ])
    .await;
    assert!(ok, "failed to remove operator label: {out}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, _out) = run_cli(&[
            "sandbox",
            "create",
            "--workspace",
            &ns,
            "--name",
            "lbl-sb2",
            "--",
            "sh",
            "-c",
            DURABLE_MAIN_SCRIPT,
            "_",
            "should-fail",
        ])
        .await;
        if !ok {
            break;
        }
        // Sandbox was created despite label removal — clean it up and retry.
        let _ = run_cli(&["sandbox", "delete", "lbl-sb2", "--workspace", &ns]).await;
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "sandbox creation still succeeds 30s after operator label removal; \
                 watcher did not remove namespace from allowlist"
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    delete_namespace(&ns).await;
}
