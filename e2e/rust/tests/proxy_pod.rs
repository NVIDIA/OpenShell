// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-proxy-pod")]

//! Capability-scoped coverage for the Kubernetes `proxy-pod` topology.
//!
//! The generic Kubernetes suite (e.g. `smoke`) assumes an in-sandbox
//! supervisor: it execs a command and reads its captured output. `proxy-pod`
//! has no supervisor in the workload pod, so those tests cannot pass and are
//! not run for this topology. This suite instead verifies the contract
//! `proxy-pod` actually offers:
//!
//! - a workload whose entrypoint is set through `containers.agent.command`
//!   reaches `Ready` (the canonical `-- <command>` path needs a supervisor and
//!   does not apply here);
//! - relay-backed operations (`exec`) are rejected with a clear,
//!   topology-specific error rather than hanging or failing opaquely.
//!
//! The NetworkPolicy egress boundary itself is asserted at the unit level in
//! `openshell-driver-kubernetes` (generated policy shape) and validated
//! manually on a policy-enforcing cluster; a self-probing egress e2e requires a
//! workload image that tests its own egress and reports through `openshell
//! logs`, which is tracked as follow-up.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::output::strip_ansi;

/// Driver config that sets a long-running workload entrypoint. Required for
/// `proxy-pod`, whose image is run directly with no supervisor to launch a
/// canonical process.
const SLEEP_ENTRYPOINT: &str =
    r#"{"kubernetes":{"containers":{"agent":{"command":["sleep","3600"]}}}}"#;

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

/// A workload whose entrypoint is supplied through driver config reaches
/// `Ready`, and relay-backed operations are rejected with a topology-specific
/// error.
#[tokio::test]
async fn proxy_pod_runs_workload_and_rejects_sessions() {
    let name = "e2e-proxy-pod";
    // Best-effort cleanup from a previous interrupted run.
    delete_sandbox(name).await;

    // Detached create: proxy-pod cannot open a session, so a non-detached
    // create would report the sessionless topology instead of returning.
    let mut create = openshell_cmd();
    create
        .arg("sandbox")
        .arg("create")
        .arg("--name")
        .arg(name)
        .arg("--detach")
        .arg("--driver-config-json")
        .arg(SLEEP_ENTRYPOINT)
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
        "proxy-pod create with an entrypoint override should succeed:\n{create_text}",
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

    // Relay-backed operations must fail fast with a topology-specific error,
    // not hang or surface an opaque ssh failure.
    let mut exec = openshell_cmd();
    exec.arg("sandbox")
        .arg("exec")
        .arg(name)
        .arg("--")
        .arg("echo")
        .arg("hi")
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
        !exec_out.status.success(),
        "exec against a sessionless topology must fail:\n{exec_text}",
    );
    assert!(
        exec_text.contains("no supervisor inside the sandbox")
            || exec_text.contains("SSH, exec, port forwarding"),
        "exec failure should name the topology limitation:\n{exec_text}",
    );

    delete_sandbox(name).await;
}
