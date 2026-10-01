// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::path::Path;
use std::time::Duration;

use openshell_e2e::harness::cli::{
    run_cli, wait_for_healthy, wait_for_sandbox_exec_contains, wait_for_sandbox_phase,
};
use openshell_e2e::harness::gateway::ManagedGateway;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;

async fn fingerprint(name: &str) -> String {
    let (output, code) = run_cli(&["sandbox", "get", name, "--output", "json"]).await;
    assert_eq!(code, 0, "sandbox get failed: {output}");
    let sandbox: serde_json::Value = serde_json::from_str(&strip_ansi(&output)).unwrap();
    let fingerprint = sandbox["host_key_fingerprint"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(fingerprint.starts_with("SHA256:"));
    let (output, code) = run_cli(&["sandbox", "list", "--output", "json"]).await;
    assert_eq!(code, 0, "sandbox list failed: {output}");
    let list: serde_json::Value = serde_json::from_str(&strip_ansi(&output)).unwrap();
    let listed = list["sandboxes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sandbox| sandbox["name"] == name)
        .unwrap();
    assert_eq!(listed["host_key_fingerprint"], fingerprint);
    fingerprint
}

async fn pinned_ssh(config: &Path, known_hosts: &Path, name: &str, first: bool) {
    let output = tokio::time::timeout(
        Duration::from_secs(30),
        tokio::process::Command::new("ssh")
            .kill_on_drop(true)
            .arg("-F")
            .arg(config)
            .arg("-o")
            .arg(if first {
                "StrictHostKeyChecking=accept-new"
            } else {
                "StrictHostKeyChecking=yes"
            })
            .arg("-o")
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .arg("-o")
            .arg("BatchMode=yes")
            .arg(format!("openshell-{name}.default"))
            .args(["printf", "ssh-identity-ok"])
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "pinned SSH failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "ssh-identity-ok");
}

#[tokio::test]
async fn ssh_host_identity_survives_restarts_and_changes_after_recreation() {
    let mut sandbox = SandboxGuard::create(&[]).await.unwrap();
    let name = sandbox.name.clone();
    let original = fingerprint(&name).await;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("ssh_config");
    let known_hosts = directory.path().join("known_hosts");
    let (output, code) = run_cli(&["sandbox", "ssh-config", &name]).await;
    assert_eq!(code, 0, "SSH config failed: {output}");
    std::fs::write(&config, output).unwrap();
    pinned_ssh(&config, &known_hosts, &name, true).await;
    let key = tokio::process::Command::new("ssh-keygen")
        .args(["-l", "-E", "sha256", "-f"])
        .arg(&known_hosts)
        .output()
        .await
        .unwrap();
    assert!(key.status.success());
    assert!(
        String::from_utf8_lossy(&key.stdout)
            .split_whitespace()
            .any(|word| word == original)
    );
    sandbox
        .exec(&["sh", "-c", "test ! -r /.openshell/supervisor/auth.json"])
        .await
        .unwrap();

    let (output, code) = run_cli(&["sandbox", "stop", &name]).await;
    assert_eq!(code, 0, "stop failed: {output}");
    wait_for_sandbox_phase(&name, "Stopped", Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(fingerprint(&name).await, original);
    let (output, code) = run_cli(&["sandbox", "start", &name]).await;
    assert_eq!(code, 0, "start failed: {output}");
    wait_for_sandbox_phase(&name, "Ready", Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(fingerprint(&name).await, original);
    pinned_ssh(&config, &known_hosts, &name, false).await;

    if let Some(gateway) = ManagedGateway::from_env().unwrap() {
        gateway.stop().unwrap();
        gateway.start().unwrap();
        wait_for_healthy(Duration::from_secs(120)).await.unwrap();
        wait_for_sandbox_phase(&name, "Ready", Duration::from_secs(120))
            .await
            .unwrap();
        wait_for_sandbox_exec_contains(
            &name,
            &["printf", "ssh-identity-ready"],
            "ssh-identity-ready",
            Duration::from_secs(240),
        )
        .await
        .unwrap();
        assert_eq!(fingerprint(&name).await, original);
        pinned_ssh(&config, &known_hosts, &name, false).await;
    } else {
        eprintln!("Skipping gateway restart check: this run uses an existing gateway");
    }

    sandbox.cleanup().await;
    let mut replacement = SandboxGuard::create(&["--name", &name]).await.unwrap();
    assert_ne!(fingerprint(&name).await, original);
    replacement.cleanup().await;
}
