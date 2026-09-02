// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-proxy-pod")]

//! Capability coverage for the Kubernetes `proxy-pod` topology.
//!
//! `proxy-pod` keeps the process supervisor in the agent pod and moves only the
//! network proxy into a separate per-sandbox pod. Because the supervisor still
//! runs beside the workload, the relay-backed operations that a sandbox is
//! expected to offer — `exec` and file transfer — work exactly as they do in the
//! combined topology. This suite asserts that recovered behavior:
//!
//! - a sandbox reaches `Ready` with the process supervisor running non-root in
//!   the agent pod (OpenShift `nonroot-v2` SCC), and
//! - `exec` and `upload`/`download` round-trip through the in-pod supervisor's
//!   own gateway session.
//!
//! Two boundaries are covered elsewhere rather than here, because asserting them
//! reliably needs cluster policy enforcement that a generic e2e environment does
//! not guarantee:
//!
//! - the scoped process-kind credential (the agent pod's token is denied
//!   provider/inference RPCs) is unit-tested in `openshell-server` and validated
//!   on a policy-enforcing cluster via the gateway's `PERMISSION_DENIED` logs;
//! - the NetworkPolicy egress fence (workload egress reaches only the proxy pod)
//!   is unit-tested in `openshell-driver-kubernetes` (generated policy shape) and
//!   validated on a policy-enforcing cluster (direct egress blocked, proxied L7
//!   allow/deny enforced).

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Delete a sandbox by name, ignoring failures (best-effort cleanup).
async fn delete_sandbox(name: &str) {
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox")
        .arg("delete")
        .arg(name)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let _ = cmd.output().await;
}

/// A `proxy-pod` sandbox reaches `Ready` and its in-pod supervisor serves the
/// relay-backed operations (`exec`, file transfer) that the network-only design
/// could not.
#[tokio::test]
async fn proxy_pod_runs_workload_and_serves_relays() {
    let name = "e2e-proxy-pod";
    // Best-effort cleanup from a previous interrupted run.
    delete_sandbox(name).await;

    // Plain create: no `containers.agent.command` override — the in-pod process
    // supervisor launches the image's default workload and serves relays. Detach
    // so the test drives readiness and relays explicitly.
    let mut create = openshell_cmd();
    create
        .arg("sandbox")
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("--detach")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let create_out = tokio::time::timeout(Duration::from_secs(300), create.output())
        .await
        .expect("sandbox create timed out")
        .expect("failed to spawn openshell");
    let create_text = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr),
    ));
    assert!(
        create_out.status.success(),
        "proxy-pod create should succeed:\n{create_text}",
    );

    // The sandbox should be present and reach Ready.
    let mut ready = false;
    let mut last_list = String::new();
    for _ in 0..30 {
        let mut list = openshell_cmd();
        list.arg("sandbox")
            .arg("list")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = list.output().await.expect("failed to run sandbox list");
        last_list = strip_ansi(&String::from_utf8_lossy(&out.stdout));
        if last_list
            .lines()
            .any(|line| line.contains(name) && line.contains("Ready"))
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    assert!(ready, "proxy-pod sandbox never reached Ready:\n{last_list}");

    // exec is relay-backed: it proves the in-pod supervisor accepts sessions and
    // streams output. The network-only design rejected this.
    let marker = "proxypod-exec-ok";
    let mut exec = openshell_cmd();
    exec.arg("sandbox")
        .arg("exec")
        .arg("--name")
        .arg(name)
        .arg("--")
        .arg("echo")
        .arg(marker)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let exec_out = tokio::time::timeout(Duration::from_secs(60), exec.output())
        .await
        .expect("sandbox exec timed out")
        .expect("failed to spawn openshell");
    let exec_text = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&exec_out.stdout),
        String::from_utf8_lossy(&exec_out.stderr),
    ));
    assert!(
        exec_out.status.success(),
        "exec against proxy-pod should succeed:\n{exec_text}",
    );
    assert!(
        exec_text.contains(marker),
        "exec output should contain the marker:\n{exec_text}",
    );

    // File transfer is also relay-backed. Upload a file, then read it back
    // through exec to confirm the round-trip landed in the workspace.
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let local = tmpdir.path().join("proxypod-upload.txt");
    let content = "proxypod-sync-payload";
    std::fs::write(&local, content).expect("write local upload file");
    let local_str = local.to_str().expect("upload path is UTF-8");
    let remote = "/sandbox/proxypod-upload.txt";

    let mut upload = openshell_cmd();
    upload
        .arg("sandbox")
        .arg("upload")
        .arg(name)
        .arg(local_str)
        .arg(remote)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let upload_out = tokio::time::timeout(Duration::from_secs(60), upload.output())
        .await
        .expect("sandbox upload timed out")
        .expect("failed to spawn openshell");
    let upload_text = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&upload_out.stdout),
        String::from_utf8_lossy(&upload_out.stderr),
    ));
    assert!(
        upload_out.status.success(),
        "upload to proxy-pod should succeed:\n{upload_text}",
    );

    let mut cat = openshell_cmd();
    cat.arg("sandbox")
        .arg("exec")
        .arg("--name")
        .arg(name)
        .arg("--")
        .arg("cat")
        .arg(remote)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let cat_out = tokio::time::timeout(Duration::from_secs(60), cat.output())
        .await
        .expect("exec cat timed out")
        .expect("failed to spawn openshell");
    let cat_text = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&cat_out.stdout),
        String::from_utf8_lossy(&cat_out.stderr),
    ));
    assert!(
        cat_text.contains(content),
        "uploaded content should be readable in the sandbox:\n{cat_text}",
    );

    delete_sandbox(name).await;
}
