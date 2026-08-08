// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-workspace-managed")]

//! E2E tests for managed workspace mode.
//!
//! The gateway is deployed with `workspace_mode = "managed"`, which
//! auto-creates a K8s namespace per workspace (`openshell-{gateway_id}-{ws}`)
//! and deletes it when the last sandbox is removed.
//!
//! Namespace cleanup after sandbox deletion is best-effort and depends on
//! controller finalization timing. These tests focus on verifiable behavior:
//! namespace creation, labels, ServiceAccount provisioning, and sandbox CR
//! placement in the correct namespace.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::output::strip_ansi;

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

fn managed_namespace(workspace: &str) -> String {
    format!("openshell-openshell-{workspace}")
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

fn unique_workspace(prefix: &str) -> String {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        % 100_000;
    format!("{prefix}-{ts}")
}

struct ManagedCleanup {
    workspace: String,
    sandboxes: Vec<String>,
}

impl Drop for ManagedCleanup {
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
            let ns = managed_namespace(&self.workspace);
            let _ = std::process::Command::new("kubectl")
                .args([
                    "--context",
                    &context,
                    "delete",
                    "namespace",
                    &ns,
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
async fn managed_creates_namespace_with_labels() {
    let ws = unique_workspace("mgd");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec!["mgd-sb".into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    // Create a sandbox — this triggers namespace creation.
    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "mgd-sb",
        "--",
        "echo",
        "managed-ok",
    ])
    .await;
    assert!(ok, "sandbox create failed: {out}");
    assert!(
        out.contains("managed-ok"),
        "sandbox output missing expected string: {out}"
    );

    // Verify the managed namespace was created.
    let (ok, out) = kubectl(&["get", "namespace", &ns]).await;
    assert!(ok, "managed namespace {ns} should exist: {out}");

    // Verify labels on the namespace.
    let (ok, label_out) =
        kubectl(&["get", "namespace", &ns, "-o", "jsonpath={.metadata.labels}"]).await;
    assert!(ok, "failed to read namespace labels: {label_out}");
    assert!(
        label_out.contains("openshell.ai/managed-by"),
        "namespace missing managed-by label: {label_out}"
    );
    assert!(
        label_out.contains("openshell.ai/gateway-id"),
        "namespace missing gateway-id label: {label_out}"
    );

    // Verify the ServiceAccount was created in the managed namespace.
    let (ok, _) = kubectl(&["get", "serviceaccount", "openshell-sandbox", "-n", &ns]).await;
    assert!(ok, "ServiceAccount openshell-sandbox should exist in {ns}");

    // Verify sandbox CR is in the managed namespace (not the gateway namespace).
    let (ok, out) = kubectl(&[
        "get",
        "sandbox.agents.x-k8s.io",
        "-n",
        &ns,
        "-o",
        "name",
    ])
    .await;
    assert!(ok, "sandbox CR should exist in namespace {ns}: {out}");
    assert!(
        out.contains("mgd-sb"),
        "sandbox CR name mismatch: {out}"
    );
}

#[tokio::test]
async fn managed_namespace_survives_with_remaining_sandboxes() {
    let ws = unique_workspace("mgd2");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec!["sb-a".into(), "sb-b".into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    // Create two sandboxes.
    let (ok, out) = run_cli(&[
        "sandbox", "create", "--workspace", &ws, "--name", "sb-a", "--", "echo", "a",
    ])
    .await;
    assert!(ok, "sandbox sb-a create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox", "create", "--workspace", &ws, "--name", "sb-b", "--", "echo", "b",
    ])
    .await;
    assert!(ok, "sandbox sb-b create failed: {out}");

    // Delete first sandbox — namespace should survive because sb-b still exists.
    let (ok, out) = run_cli(&["sandbox", "delete", "sb-a", "--workspace", &ws]).await;
    assert!(ok, "sandbox sb-a delete failed: {out}");

    // Brief wait, then verify the namespace still exists.
    tokio::time::sleep(Duration::from_secs(3)).await;

    let (ok, _) = kubectl(&["get", "namespace", &ns]).await;
    assert!(ok, "managed namespace {ns} should still exist with sb-b");

    // Verify sb-b's CR is still in the managed namespace.
    let (ok, out) = kubectl(&[
        "get",
        "sandbox.agents.x-k8s.io",
        "-n",
        &ns,
        "-o",
        "name",
    ])
    .await;
    assert!(ok, "sandbox CRs should still exist in {ns}: {out}");
    assert!(
        out.contains("sb-b"),
        "sb-b CR should still be present: {out}"
    );
}

#[tokio::test]
async fn managed_isolates_workspaces_into_separate_namespaces() {
    let ws_a = unique_workspace("iso-a");
    let ws_b = unique_workspace("iso-b");
    let ns_a = managed_namespace(&ws_a);
    let ns_b = managed_namespace(&ws_b);
    let _cleanup_a = ManagedCleanup {
        workspace: ws_a.clone(),
        sandboxes: vec!["sb-iso-a".into()],
    };
    let _cleanup_b = ManagedCleanup {
        workspace: ws_b.clone(),
        sandboxes: vec!["sb-iso-b".into()],
    };

    // Create two workspaces with sandboxes.
    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws_a]).await;
    assert!(ok, "workspace A create failed: {out}");
    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws_b]).await;
    assert!(ok, "workspace B create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox", "create", "--workspace", &ws_a, "--name", "sb-iso-a", "--", "echo", "a",
    ])
    .await;
    assert!(ok, "sandbox A create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox", "create", "--workspace", &ws_b, "--name", "sb-iso-b", "--", "echo", "b",
    ])
    .await;
    assert!(ok, "sandbox B create failed: {out}");

    // Verify each workspace has its own namespace.
    assert_ne!(ns_a, ns_b, "namespaces should differ");

    let (ok, _) = kubectl(&["get", "namespace", &ns_a]).await;
    assert!(ok, "namespace {ns_a} should exist");
    let (ok, _) = kubectl(&["get", "namespace", &ns_b]).await;
    assert!(ok, "namespace {ns_b} should exist");

    // Verify sandbox CRs are in the correct namespaces (no cross-contamination).
    let (ok, out) = kubectl(&[
        "get",
        "sandbox.agents.x-k8s.io",
        "-n",
        &ns_a,
        "-o",
        "name",
    ])
    .await;
    assert!(ok, "failed to list CRs in {ns_a}: {out}");
    assert!(out.contains("sb-iso-a"), "sb-iso-a should be in {ns_a}");
    assert!(!out.contains("sb-iso-b"), "sb-iso-b should NOT be in {ns_a}");

    let (ok, out) = kubectl(&[
        "get",
        "sandbox.agents.x-k8s.io",
        "-n",
        &ns_b,
        "-o",
        "name",
    ])
    .await;
    assert!(ok, "failed to list CRs in {ns_b}: {out}");
    assert!(out.contains("sb-iso-b"), "sb-iso-b should be in {ns_b}");
    assert!(!out.contains("sb-iso-a"), "sb-iso-a should NOT be in {ns_b}");
}
