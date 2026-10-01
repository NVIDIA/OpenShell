// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Run with both the default auto mode and forced bridge mode to exercise
//! authenticated gateway callbacks, interactive access, and supervisor restart.

use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::sandbox::SandboxGuard;

async fn inspect_role(name: &str, role: &str) -> serde_json::Value {
    let listed = tokio::process::Command::new("docker")
        .args([
            "ps",
            "-aq",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={name}"),
            "--filter",
            &format!("label=openshell.ai/isolation-role={role}"),
        ])
        .output()
        .await
        .expect("list sandbox containers");
    assert!(listed.status.success());
    let id = String::from_utf8(listed.stdout).unwrap();
    let id = id.trim();
    assert!(!id.is_empty(), "missing {role} container for {name}");
    let inspected = tokio::process::Command::new("docker")
        .args(["inspect", id])
        .output()
        .await
        .expect("inspect sandbox container");
    assert!(inspected.status.success());
    serde_json::from_slice::<Vec<serde_json::Value>>(&inspected.stdout)
        .unwrap()
        .remove(0)
}

#[tokio::test]
async fn supervisor_networking_preserves_boundary_and_survives_restart() {
    let policy = tempfile::NamedTempFile::new().expect("create policy file");
    std::fs::write(
        policy.path(),
        r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /bin, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
network_policies:
  host_gateway:
    name: host_gateway
    endpoints:
      - {host: host.openshell.internal, port: 8080, protocol: tcp}
    binaries:
      - {path: /usr/bin/getent}
",
    )
    .expect("write policy file");
    let mut sandbox = SandboxGuard::create(&["--policy", policy.path().to_str().unwrap()])
        .await
        .expect("create sandbox");
    let workload = inspect_role(&sandbox.name, "sandbox").await;
    let requested = std::env::var("OPENSHELL_E2E_DOCKER_SUPERVISOR_NETWORK_MODE")
        .unwrap_or_else(|_| "auto".into());
    let expected = if requested == "bridge"
        || (requested == "auto" && workload["HostConfig"]["Runtime"] == "sysbox-runc")
    {
        "bridge"
    } else {
        "host"
    };
    assert_eq!(workload["HostConfig"]["NetworkMode"], "none");
    assert!(
        workload["NetworkSettings"]["Networks"]
            .as_object()
            .is_none_or(|networks| networks.keys().all(|name| name == "none"))
    );
    let supervisor = inspect_role(&sandbox.name, "supervisor").await;
    assert_eq!(supervisor["HostConfig"]["NetworkMode"], expected);
    assert!(
        sandbox
            .exec(&["sh", "-c", "echo networking-ready"])
            .await
            .unwrap()
            .contains("networking-ready")
    );
    assert!(
        !sandbox
            .exec(&["/usr/bin/getent", "hosts", "host.openshell.internal"])
            .await
            .expect("resolve policy-approved host alias")
            .trim()
            .is_empty()
    );
    let (output, code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    wait_for_sandbox_phase(&sandbox.name, "Stopped", Duration::from_secs(60))
        .await
        .unwrap();
    let (output, code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    assert!(
        sandbox
            .exec(&["sh", "-c", "echo networking-restarted"])
            .await
            .unwrap()
            .contains("networking-restarted")
    );
    assert!(
        !sandbox
            .exec(&["/usr/bin/getent", "hosts", "host.openshell.internal"])
            .await
            .expect("resolve host alias after restart")
            .trim()
            .is_empty()
    );
    assert_eq!(
        inspect_role(&sandbox.name, "supervisor").await["HostConfig"]["NetworkMode"],
        expected
    );
    sandbox.cleanup().await;
}
