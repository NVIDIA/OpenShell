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
//! namespace creation, labels, ServiceAccount and SSH NetworkPolicy
//! provisioning, and sandbox CR placement in the correct namespace.

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

    // The managed driver copies only explicitly configured image-pull Secrets
    // from the gateway namespace into the workspace namespace.
    let (ok, copied_secret) = kubectl(&[
        "get",
        "secret",
        "e2e-regcred",
        "-n",
        &ns,
        "-o",
        "jsonpath={.type}",
    ])
    .await;
    assert!(
        ok && copied_secret.contains("kubernetes.io/dockerconfigjson"),
        "configured image-pull Secret should be copied into {ns}: {copied_secret}"
    );

    // Verify SSH ingress is restricted to the gateway peer. Because Kubernetes
    // NetworkPolicies are allowlists, the absence of a sandbox peer here
    // denies sandbox-to-sandbox TCP 2222 traffic.
    let (ok, policy) = kubectl(&[
        "get",
        "networkpolicy",
        "openshell-sandbox-ssh",
        "-n",
        &ns,
        "-o",
        "json",
    ])
    .await;
    assert!(
        ok,
        "managed SSH NetworkPolicy should exist in {ns}: {policy}"
    );
    let policy: serde_json::Value =
        serde_json::from_str(&policy).expect("managed SSH NetworkPolicy should be valid JSON");
    assert_eq!(
        policy["spec"]["podSelector"]["matchLabels"]["openshell.ai/managed-by"],
        "openshell"
    );
    assert_eq!(policy["spec"]["ingress"][0]["ports"][0]["port"], 2222);
    assert_eq!(
        policy["spec"]["ingress"][0]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"],
        "openshell"
    );
    assert!(
        policy["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]
            ["app.kubernetes.io/name"]
            .is_string(),
        "SSH ingress peer must select gateway pods: {policy}"
    );

    // Verify sandbox CR is in the managed namespace (not the gateway namespace).
    let (ok, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", "-n", &ns, "-o", "name"]).await;
    assert!(ok, "sandbox CR should exist in namespace {ns}: {out}");
    assert!(out.contains("mgd-sb"), "sandbox CR name mismatch: {out}");

    // Verify the sandbox is resolvable through the OpenShell control plane.
    let (ok, out) = run_cli(&["sandbox", "list", "--workspace", &ws]).await;
    assert!(ok, "sandbox list failed: {out}");
    assert!(
        out.contains("mgd-sb"),
        "sandbox list should find mgd-sb via control plane: {out}"
    );

    let (ok, out) = run_cli(&["sandbox", "get", "mgd-sb", "--workspace", &ws]).await;
    assert!(ok, "sandbox get failed: {out}");
    assert!(
        out.contains("mgd-sb"),
        "sandbox get should resolve mgd-sb via control plane: {out}"
    );

    // Verify sandbox delete works through the control plane (uses sandbox_lookup_selector).
    let (ok, out) = run_cli(&["sandbox", "delete", "mgd-sb", "--workspace", &ws]).await;
    assert!(ok, "sandbox delete failed: {out}");

    // Wait for the sandbox CR to be fully removed (deletion is asynchronous).
    wait_sandbox_gone(&ws, "mgd-sb").await;
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
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "sb-a",
        "--",
        "echo",
        "a",
    ])
    .await;
    assert!(ok, "sandbox sb-a create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "sb-b",
        "--",
        "echo",
        "b",
    ])
    .await;
    assert!(ok, "sandbox sb-b create failed: {out}");

    // Delete first sandbox — namespace should survive because sb-b still exists.
    let (ok, out) = run_cli(&["sandbox", "delete", "sb-a", "--workspace", &ws]).await;
    assert!(ok, "sandbox sb-a delete failed: {out}");

    // Wait for sb-a to be fully removed before checking namespace state.
    wait_sandbox_gone(&ws, "sb-a").await;

    let (ok, _) = kubectl(&["get", "namespace", &ns]).await;
    assert!(ok, "managed namespace {ns} should still exist with sb-b");

    // Verify sb-b's CR is still in the managed namespace.
    let (ok, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", "-n", &ns, "-o", "name"]).await;
    assert!(ok, "sandbox CRs should still exist in {ns}: {out}");
    assert!(
        out.contains("sb-b"),
        "sb-b CR should still be present: {out}"
    );

    // Verify sb-b is still resolvable through the OpenShell control plane.
    let (ok, out) = run_cli(&["sandbox", "list", "--workspace", &ws]).await;
    assert!(ok, "sandbox list failed: {out}");
    assert!(
        out.contains("sb-b"),
        "sandbox list should find sb-b via control plane: {out}"
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
        "sandbox",
        "create",
        "--workspace",
        &ws_a,
        "--name",
        "sb-iso-a",
        "--",
        "echo",
        "a",
    ])
    .await;
    assert!(ok, "sandbox A create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws_b,
        "--name",
        "sb-iso-b",
        "--",
        "echo",
        "b",
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
    let (ok, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", "-n", &ns_a, "-o", "name"]).await;
    assert!(ok, "failed to list CRs in {ns_a}: {out}");
    assert!(out.contains("sb-iso-a"), "sb-iso-a should be in {ns_a}");
    assert!(
        !out.contains("sb-iso-b"),
        "sb-iso-b should NOT be in {ns_a}"
    );

    let (ok, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", "-n", &ns_b, "-o", "name"]).await;
    assert!(ok, "failed to list CRs in {ns_b}: {out}");
    assert!(out.contains("sb-iso-b"), "sb-iso-b should be in {ns_b}");
    assert!(
        !out.contains("sb-iso-a"),
        "sb-iso-a should NOT be in {ns_b}"
    );

    // Verify workspace isolation through the OpenShell control plane.
    let (ok, out) = run_cli(&["sandbox", "list", "--workspace", &ws_a]).await;
    assert!(ok, "sandbox list ws_a failed: {out}");
    assert!(
        out.contains("sb-iso-a"),
        "sandbox list ws_a should find sb-iso-a: {out}"
    );
    assert!(
        !out.contains("sb-iso-b"),
        "sandbox list ws_a should NOT find sb-iso-b: {out}"
    );

    let (ok, out) = run_cli(&["sandbox", "list", "--workspace", &ws_b]).await;
    assert!(ok, "sandbox list ws_b failed: {out}");
    assert!(
        out.contains("sb-iso-b"),
        "sandbox list ws_b should find sb-iso-b: {out}"
    );
    assert!(
        !out.contains("sb-iso-a"),
        "sandbox list ws_b should NOT find sb-iso-a: {out}"
    );
}

#[tokio::test]
async fn managed_workspace_delete_removes_namespace() {
    let ws = unique_workspace("mgddel");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec!["del-sb".into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "del-sb",
        "--",
        "echo",
        "del-ok",
    ])
    .await;
    assert!(ok, "sandbox create failed: {out}");
    assert!(
        out.contains("del-ok"),
        "sandbox output missing expected string: {out}"
    );

    let (ok, _) = kubectl(&["get", "namespace", &ns]).await;
    assert!(
        ok,
        "managed namespace {ns} should exist after sandbox create"
    );

    let (ok, out) = run_cli(&["sandbox", "delete", "del-sb", "--workspace", &ws]).await;
    assert!(ok, "sandbox delete failed: {out}");

    wait_sandbox_gone(&ws, "del-sb").await;

    let (ok, out) = run_cli(&["workspace", "delete", &ws]).await;
    assert!(ok, "workspace delete failed: {out}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (exists, _) = kubectl(&["get", "namespace", &ns]).await;
        if !exists {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("managed namespace {ns} still exists 30s after workspace delete");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn managed_tls_secret_copied_to_namespace() {
    let (ok, config_out) = kubectl(&[
        "get",
        "configmap",
        "openshell-config",
        "-n",
        "openshell",
        "-o",
        "jsonpath={.data.gateway\\.toml}",
    ])
    .await;
    if !ok || !config_out.contains("client_tls_secret_name") {
        eprintln!("SKIP: client_tls_secret_name not configured; TLS secret copying disabled");
        return;
    }

    let ws = unique_workspace("mgdtls");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec!["tls-sb".into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "tls-sb",
        "--",
        "echo",
        "tls-ok",
    ])
    .await;
    assert!(ok, "sandbox create failed: {out}");
    assert!(
        out.contains("tls-ok"),
        "sandbox output missing expected string: {out}"
    );

    let (ok, out) = kubectl(&["get", "secret", "openshell-client-tls", "-n", &ns]).await;
    assert!(
        ok,
        "TLS secret openshell-client-tls should be copied to managed namespace {ns}: {out}"
    );

    let (ok, label_out) = kubectl(&[
        "get",
        "secret",
        "openshell-client-tls",
        "-n",
        &ns,
        "-o",
        "jsonpath={.metadata.labels}",
    ])
    .await;
    assert!(ok, "failed to read TLS secret labels: {label_out}");
    assert!(
        label_out.contains("openshell.ai/managed-by"),
        "copied TLS secret missing managed-by label: {label_out}"
    );
}

#[tokio::test]
async fn managed_rejects_namespace_owned_by_different_gateway() {
    let ws = unique_workspace("mgdown");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec![],
    };

    let (ok, out) = kubectl(&["create", "namespace", &ns]).await;
    assert!(ok, "failed to pre-create namespace {ns}: {out}");

    let (ok, out) = kubectl(&[
        "label",
        "namespace",
        &ns,
        "openshell.ai/managed-by=openshell",
        "openshell.ai/gateway-id=wrong-gateway",
    ])
    .await;
    assert!(ok, "failed to label namespace: {out}");

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "conflict-sb",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(
        !ok,
        "sandbox create should fail for namespace owned by different gateway, but succeeded: {out}"
    );
}

#[tokio::test]
async fn managed_full_lifecycle_with_multiple_sandboxes() {
    let ws = unique_workspace("mgdlc");
    let ns = managed_namespace(&ws);
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec!["lc-a".into(), "lc-b".into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "lc-a",
        "--",
        "echo",
        "a",
    ])
    .await;
    assert!(ok, "sandbox lc-a create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "lc-b",
        "--",
        "echo",
        "b",
    ])
    .await;
    assert!(ok, "sandbox lc-b create failed: {out}");

    let (ok, _) = kubectl(&["get", "namespace", &ns]).await;
    assert!(ok, "managed namespace {ns} should exist");

    let (ok, out) = run_cli(&["sandbox", "delete", "lc-a", "--workspace", &ws]).await;
    assert!(ok, "sandbox lc-a delete failed: {out}");

    wait_sandbox_gone(&ws, "lc-a").await;

    let (ok, _) = kubectl(&["get", "namespace", &ns]).await;
    assert!(
        ok,
        "managed namespace {ns} should still exist with lc-b remaining"
    );

    let (ok, out) = run_cli(&["sandbox", "delete", "lc-b", "--workspace", &ws]).await;
    assert!(ok, "sandbox lc-b delete failed: {out}");

    wait_sandbox_gone(&ws, "lc-b").await;

    let (ok, out) = run_cli(&["workspace", "delete", &ws]).await;
    assert!(ok, "workspace delete failed: {out}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (exists, _) = kubectl(&["get", "namespace", &ns]).await;
        if !exists {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("managed namespace {ns} still exists 30s after full lifecycle cleanup");
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

#[tokio::test]
async fn managed_stop_waits_for_workspace_pod_to_disappear() {
    let (ok, sandbox_api_version) = kubectl(&[
        "get",
        "crd",
        "sandboxes.agents.x-k8s.io",
        "-o",
        "jsonpath={.spec.versions[?(@.storage==true)].name}",
    ])
    .await;
    assert!(
        ok,
        "failed to resolve Sandbox API version: {sandbox_api_version}"
    );
    if sandbox_api_version.trim() != "v1alpha1" {
        eprintln!("SKIP: legacy pod-disappearance fallback applies only to Sandbox API v1alpha1");
        return;
    }

    let ws = unique_workspace("mgdstop");
    let ns = managed_namespace(&ws);
    let sandbox = "stop-sb";
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec![sandbox.into()],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        sandbox,
        "--",
        "echo",
        "ready",
    ])
    .await;
    assert!(ok, "sandbox create failed: {out}");

    let (ok, pod_name) = kubectl(&[
        "get",
        "sandbox",
        sandbox,
        "-n",
        &ns,
        "-o",
        "jsonpath={.metadata.annotations.agents\\.x-k8s\\.io/pod-name}",
    ])
    .await;
    assert!(ok, "failed to resolve sandbox pod name: {pod_name}");
    let pod_name = pod_name.trim();
    assert!(!pod_name.is_empty(), "sandbox pod annotation was empty");

    let (ok, out) = run_cli(&["sandbox", "stop", sandbox, "--workspace", &ws]).await;
    assert!(ok, "sandbox stop failed: {out}");

    let (exists, out) = kubectl(&["get", "pod", pod_name, "-n", &ns]).await;
    assert!(
        !exists,
        "sandbox stop returned before workspace pod {pod_name} disappeared: {out}"
    );
}

#[tokio::test]
async fn managed_rejects_invalid_dns1123_sandbox_name() {
    let ws = unique_workspace("mgddns");
    let _cleanup = ManagedCleanup {
        workspace: ws.clone(),
        sandboxes: vec![],
    };

    let (ok, out) = run_cli(&["workspace", "create", "--name", &ws]).await;
    assert!(ok, "workspace create failed: {out}");

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "my_bad_name",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(
        !ok,
        "sandbox with underscore name should be rejected: {out}"
    );
    assert!(
        out.contains("lowercase alphanumeric"),
        "error should mention character constraint: {out}"
    );

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "MyBadName",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(!ok, "sandbox with uppercase name should be rejected: {out}");
    assert!(
        out.contains("lowercase alphanumeric"),
        "error should mention character constraint: {out}"
    );

    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        &ws,
        "--name",
        "trailing-",
        "--",
        "echo",
        "nope",
    ])
    .await;
    assert!(
        !ok,
        "sandbox with trailing hyphen should be rejected: {out}"
    );
    let normalized: String = out
        .chars()
        .filter(|c| *c != '│')
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        normalized.contains("must not start or end with a hyphen"),
        "error should mention hyphen constraint: {out}"
    );
}
