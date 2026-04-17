// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! Regression test for the openshell namespace auto-create.
//!
//! `reconcile_pki` waits up to ~115s for `namespace/openshell` before the
//! PKI phase can read or write secrets. The namespace is declared by a
//! standalone manifest at `deploy/kube/manifests/openshell-namespace.yaml`
//! that k3s auto-applies before the Helm controller reconciles the
//! openshell chart — without it, slow networks or cold boots race the
//! Helm controller and `wait_for_namespace` times out.
//!
//! This test runs against a healthy gateway and asserts the namespace is
//! present in the cluster. Closes NVIDIA/NemoClaw#1974.

use std::process::{Command, Stdio};

use openshell_e2e::harness::output::strip_ansi;

/// Resolve the gateway name from `OPENSHELL_GATEWAY`, falling back to the
/// CI default of `"openshell"` — same convention as `gateway_resume`.
fn gateway_name() -> String {
    std::env::var("OPENSHELL_GATEWAY").unwrap_or_else(|_| "openshell".to_string())
}

/// Docker container name for the e2e gateway.
fn container_name() -> String {
    format!("openshell-cluster-{}", gateway_name())
}

/// Run `kubectl` against the gateway's embedded k3s cluster via
/// `docker exec` and return (stdout, stderr, exit-code).
fn kubectl_in_cluster(args: &str) -> (String, String, i32) {
    let cname = container_name();
    let output = Command::new("docker")
        .args([
            "exec",
            &cname,
            "sh",
            "-c",
            &format!("KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl {args}"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn docker exec kubectl");

    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

#[tokio::test]
async fn openshell_namespace_exists_after_cluster_start() {
    let (stdout, stderr, code) = kubectl_in_cluster("get namespace openshell -o name");
    assert_eq!(
        code, 0,
        "`kubectl get namespace openshell` must succeed after gateway start. \
         stdout=<{}> stderr=<{}>",
        strip_ansi(&stdout),
        strip_ansi(&stderr),
    );
    assert_eq!(
        stdout.trim(),
        "namespace/openshell",
        "unexpected kubectl output: <{}>",
        strip_ansi(&stdout),
    );
}

#[tokio::test]
async fn openshell_namespace_is_active() {
    // A Namespace can exist in the `Terminating` phase during cluster
    // tear-down — assert we see the healthy `Active` phase, not just
    // bare existence. This also rejects an empty-phase response that a
    // transient API error could produce.
    let (stdout, stderr, code) =
        kubectl_in_cluster("get namespace openshell -o jsonpath={.status.phase}");
    assert_eq!(
        code, 0,
        "jsonpath query for openshell namespace phase must succeed. \
         stdout=<{}> stderr=<{}>",
        strip_ansi(&stdout),
        strip_ansi(&stderr),
    );
    assert_eq!(
        stdout.trim(),
        "Active",
        "openshell namespace must be in Active phase, got: <{}>",
        strip_ansi(&stdout),
    );
}
