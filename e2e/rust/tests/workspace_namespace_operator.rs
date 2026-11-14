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

async fn wait_sandbox_gone(workspace: &str, sandbox: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let (ok, out) = run_cli(&["sandbox", "list", "--workspace", workspace]).await;
        if ok && !out.contains(sandbox) {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox {sandbox} still listed in workspace {workspace} 30s after delete: {out}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn provision_operator_namespace(name: &str) {
    let (ok, out) = kubectl(&["create", "namespace", name]).await;
    assert!(ok, "failed to create namespace {name}: {out}");

    let (ok, out) = kubectl(&["label", "namespace", name, OPERATOR_LABEL]).await;
    assert!(ok, "failed to label namespace {name}: {out}");

    let (ok, out) = install_workspace_chart(name).await;
    assert!(ok, "failed to install workspace chart in {name}: {out}");
}

async fn install_workspace_chart(namespace: &str) -> (bool, String) {
    let chart = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/helm/openshell-workspace"
    );
    let output = tokio::process::Command::new("helm")
        .args([
            "--kube-context",
            &kube_context(),
            "install",
            "openshell-workspace",
            chart,
            "--namespace",
            namespace,
            "--wait",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("failed to spawn helm");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    (output.status.success(), combined)
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

const GATEWAY_SERVICE_ACCOUNT: &str = "system:serviceaccount:openshell:openshell";

async fn gateway_can(verb: &str, resource: &str, namespace: &str) -> bool {
    let (_, out) = kubectl(&[
        "auth",
        "can-i",
        verb,
        resource,
        "-n",
        namespace,
        "--as",
        GATEWAY_SERVICE_ACCOUNT,
    ])
    .await;
    match out.trim() {
        "yes" => true,
        "no" => false,
        other => panic!("unexpected kubectl auth can-i output for {verb} {resource}: {other}"),
    }
}

#[tokio::test]
async fn operator_gateway_has_no_secret_access_without_workspace_chart() {
    let ns = unique_namespace("oprbac");

    for verb in ["get", "list", "create", "patch", "delete"] {
        assert!(
            !gateway_can(verb, "secrets", &ns).await,
            "gateway must not {verb} Secrets in namespace {ns} without the workspace chart"
        );
    }
    assert!(
        !gateway_can("patch", "secrets/openshell-client-tls", &ns).await,
        "gateway must not patch the client TLS Secret in namespace {ns} without the workspace chart"
    );
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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let sandbox_out = loop {
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
            break out;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox create did not succeed within 30s: {out}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
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

async fn create_identity_sandbox(namespace: &str, name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_mins(1);
    loop {
        let (ok, out) = run_cli(&[
            "sandbox", "create", "--workspace", namespace, "--name", name, "--detach", "--",
            "sh", "-c", "set -eu; if ! test -f /sandbox/canonical-identity; then printf '%s:%s\\n' \"$(id -u)\" \"$(id -g)\" > /sandbox/canonical-identity; sync; fi; exec sleep infinity",
        ]).await;
        if ok {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "identity sandbox create failed: {out}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn cli_error_contains(output: &str, expected: &str) -> bool {
    // Miette wraps identifiers at punctuation and decorates continuation
    // lines. Compare the error content independently of terminal width.
    let compact = |text: &str| {
        text.chars()
            .filter(|character| !character.is_whitespace() && *character != '│')
            .collect::<String>()
    };
    compact(output).contains(&compact(expected))
}

async fn assert_identity_create_rejected(namespace: &str, name: &str, expected: &str) {
    let (ok, out) = run_cli(&[
        "sandbox",
        "create",
        "--workspace",
        namespace,
        "--name",
        name,
        "--detach",
        "--",
        "true",
    ])
    .await;
    assert!(
        !ok && cli_error_contains(&out, expected),
        "invalid namespace identity was not rejected and explained: {out}"
    );
    let (exists, out) = kubectl(&["get", "sandbox.agents.x-k8s.io", name, "-n", namespace]).await;
    assert!(
        !exists,
        "invalid namespace identity created a workload: {out}"
    );
}

async fn assert_tenant_identity(namespace: &str, sandbox: &str, uid: u32, gid: u32) {
    let script = format!(
        "set -eu; test \"$(id -u):$(id -g)\" = '{uid}:{gid}'; test \"$(cat /sandbox/canonical-identity)\" = '{uid}:{gid}'; test \"$(stat -c %u:%g /sandbox/canonical-identity)\" = '{uid}:{gid}'; echo tenant-identity-ok"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_mins(2);
    loop {
        let (ok, out) = run_cli(&[
            "sandbox",
            "exec",
            "--workspace",
            namespace,
            "--name",
            sandbox,
            "--no-tty",
            "--",
            "sh",
            "-c",
            &script,
        ])
        .await;
        if ok {
            assert!(out.contains("tenant-identity-ok"), "{out}");
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "tenant exec identity failed: {out}"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    let (ok, out) = run_cli(&[
        "sandbox",
        "get",
        sandbox,
        "--workspace",
        namespace,
        "--output",
        "json",
    ])
    .await;
    assert!(ok, "sandbox status failed: {out}");
    let status: serde_json::Value = serde_json::from_str(&out).expect("sandbox status JSON");
    assert!(
        status["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|condition| {
                condition["type"] == "WorkloadIdentity"
                    && condition["message"] == format!("Resolved workload UID:GID is {uid}:{gid}")
            }),
        "status must expose assigned identity: {status}"
    );
    let (ok, out) = kubectl(&[
        "get",
        "sandbox.agents.x-k8s.io",
        sandbox,
        "-n",
        namespace,
        "-o",
        "json",
    ])
    .await;
    assert!(ok, "sandbox template read failed: {out}");
    let object: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(
        object["spec"]["podTemplate"]["spec"]["securityContext"]["fsGroup"],
        gid
    );
}

#[tokio::test]
async fn operator_namespace_workload_identity_is_pinned_across_restart() {
    let tenant_a = unique_namespace("opidentity-a");
    let tenant_b = unique_namespace("opidentity-b");
    let _cleanup_a = OperatorCleanup {
        workspace: tenant_a.clone(),
        namespace: tenant_a.clone(),
        sandboxes: vec![
            "identity".into(),
            "new-identity".into(),
            "invalid-identity".into(),
            "missing-identity".into(),
            "incomplete-identity".into(),
        ],
    };
    let _cleanup_b = OperatorCleanup {
        workspace: tenant_b.clone(),
        namespace: tenant_b.clone(),
        sandboxes: vec!["identity".into()],
    };
    for (namespace, uid, gid) in [(&tenant_a, 1500, 1600), (&tenant_b, 1700, 1800)] {
        provision_operator_namespace(namespace).await;
        let (ok, out) = run_cli(&["workspace", "create", "--name", namespace]).await;
        assert!(ok, "workspace create failed: {out}");
        if namespace == &tenant_a
            && std::env::var("OPENSHELL_E2E_REQUIRE_NAMESPACE_IDENTITY").as_deref() == Ok("1")
        {
            assert_identity_create_rejected(
                namespace,
                "missing-identity",
                "namespace identity requires both",
            )
            .await;
        }
        let (ok, out) = kubectl(&[
            "annotate",
            "namespace",
            namespace,
            &format!("openshell.ai/sandbox-uid={uid}"),
            &format!("openshell.ai/sandbox-gid={gid}"),
        ])
        .await;
        assert!(ok, "namespace identity assignment failed: {out}");
        create_identity_sandbox(namespace, "identity").await;
        assert_tenant_identity(namespace, "identity", uid, gid).await;
    }
    let (ok, out) = kubectl(&[
        "annotate",
        "namespace",
        &tenant_a,
        "--overwrite",
        "openshell.ai/sandbox-uid=1900",
        "openshell.ai/sandbox-gid=2000",
    ])
    .await;
    assert!(ok, "change assignment failed: {out}");
    assert_tenant_identity(&tenant_a, "identity", 1500, 1600).await;
    let (ok, out) = run_cli(&["sandbox", "stop", "identity", "--workspace", &tenant_a]).await;
    assert!(ok, "stop failed: {out}");
    let (ok, out) = run_cli(&["sandbox", "get", "identity", "--workspace", &tenant_a]).await;
    assert!(
        ok && out.contains("1500:1600"),
        "stopped status lost identity: {out}"
    );
    let (ok, out) = run_cli(&["sandbox", "start", "identity", "--workspace", &tenant_a]).await;
    assert!(ok, "start failed: {out}");
    assert_tenant_identity(&tenant_a, "identity", 1500, 1600).await;
    assert_tenant_identity(&tenant_b, "identity", 1700, 1800).await;
    create_identity_sandbox(&tenant_a, "new-identity").await;
    assert_tenant_identity(&tenant_a, "new-identity", 1900, 2000).await;

    // An invalid operator assignment must fail before a workload is created.
    let (ok, out) = kubectl(&[
        "annotate",
        "namespace",
        &tenant_a,
        "--overwrite",
        "openshell.ai/sandbox-gid=0",
    ])
    .await;
    assert!(ok, "invalid assignment fixture failed: {out}");
    assert_identity_create_rejected(
        &tenant_a,
        "invalid-identity",
        "openshell.ai/sandbox-gid must be a decimal integer between 1 and 4294967294",
    )
    .await;
    let (ok, out) = kubectl(&[
        "annotate",
        "namespace",
        &tenant_a,
        "openshell.ai/sandbox-gid-",
    ])
    .await;
    assert!(ok, "incomplete assignment fixture failed: {out}");
    assert_identity_create_rejected(
        &tenant_a,
        "incomplete-identity",
        "namespace identity requires both",
    )
    .await;
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
            "echo",
            "opdel-ok",
        ])
        .await;
        if ok {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox create did not succeed within 30s: {out}"
        );
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
            "echo",
            "lbl-ok",
        ])
        .await;
        if ok {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox create did not succeed within 30s: {out}"
        );
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
            "echo",
            "should-fail",
        ])
        .await;
        if !ok {
            break;
        }
        // Sandbox was created despite label removal — clean it up and retry.
        let _ = run_cli(&["sandbox", "delete", "lbl-sb2", "--workspace", &ns]).await;
        assert!(
            tokio::time::Instant::now() < deadline,
            "sandbox creation still succeeds 30s after operator label removal; \
             watcher did not remove namespace from allowlist"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    delete_namespace(&ns).await;
}
