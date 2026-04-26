// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! E2E test: verify Kubernetes user namespace pod spec generation.
//!
//! Enables `OPENSHELL_ENABLE_USER_NAMESPACES` on the gateway, triggers sandbox
//! creation, and inspects the resulting pod spec to confirm:
//!   1. `spec.hostUsers` is `false`
//!   2. The container security context includes the extra capabilities
//!      (SETUID, SETGID, DAC_READ_SEARCH) required for user namespace operation
//!
//! The sandbox pod may fail to start in Docker-in-Docker dev clusters where the
//! filesystem does not support ID-mapped mounts. The test inspects the pod spec
//! regardless of runtime success.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;

async fn kubectl(args: &[&str]) -> Result<String, String> {
    let output = tokio::process::Command::new("docker")
        .args(["exec", "openshell-cluster-openshell", "kubectl"])
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| format!("failed to run kubectl: {e}"))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();

    if !output.status.success() {
        return Err(format!("kubectl {args:?} failed: {stdout}{stderr}"));
    }
    Ok(stdout)
}

async fn set_user_namespaces(enable: bool) -> Result<(), String> {
    let env_arg = if enable {
        "OPENSHELL_ENABLE_USER_NAMESPACES=true"
    } else {
        "OPENSHELL_ENABLE_USER_NAMESPACES-"
    };

    kubectl(&[
        "set", "env", "statefulset/openshell",
        "-n", "openshell", env_arg,
    ]).await?;

    kubectl(&[
        "rollout", "status", "statefulset/openshell",
        "-n", "openshell", "--timeout=120s",
    ]).await?;

    // Give the gateway time to fully initialize after rollout.
    tokio::time::sleep(Duration::from_secs(5)).await;

    Ok(())
}

async fn delete_sandbox(name: &str) {
    let _ = kubectl(&["delete", "sandbox", name, "-n", "openshell"]).await;
}

/// Find a sandbox pod by its sandbox CRD name. The CRD controller creates a
/// pod with the same name as the Sandbox resource.
async fn wait_for_sandbox_pod(name: &str, timeout_secs: u64) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
    while tokio::time::Instant::now() < deadline {
        if let Ok(n) = kubectl(&[
            "get", "pod", name, "-n", "openshell",
            "-o", "jsonpath={.metadata.name}",
        ]).await {
            if !n.trim().is_empty() {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    Err(format!("sandbox pod {name} did not appear within {timeout_secs}s"))
}

#[tokio::test]
async fn sandbox_pod_spec_has_user_namespace_fields() {
    // Enable user namespaces on the gateway.
    set_user_namespaces(true)
        .await
        .expect("failed to enable user namespaces on gateway");

    // Start sandbox creation in the background. The pod may never become
    // ready in DinD environments, so we spawn the CLI and inspect the pod
    // spec independently.
    let mut cmd = openshell_cmd();
    cmd.arg("sandbox").arg("create")
        .arg("--").arg("sleep").arg("infinity");
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let child = cmd.spawn().expect("failed to spawn openshell create");

    // Wait for the sandbox CRD to be created by polling.
    let mut sandbox_name = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < deadline {
        if let Ok(names) = kubectl(&[
            "get", "sandbox", "-n", "openshell",
            "-o", "jsonpath={.items[*].metadata.name}",
        ]).await {
            let latest = names.split_whitespace()
                .filter(|n| *n != "openshell-0")
                .last()
                .map(|s| s.to_string());
            if latest.is_some() {
                sandbox_name = latest;
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    let name = match sandbox_name {
        Some(n) => n,
        None => {
            drop(child);
            set_user_namespaces(false).await.ok();
            panic!("no sandbox CRD found within 60s");
        }
    };

    // Wait for the pod to be created (the CRD controller creates it).
    if let Err(e) = wait_for_sandbox_pod(&name, 60).await {
        drop(child);
        delete_sandbox(&name).await;
        set_user_namespaces(false).await.ok();
        panic!("{e}");
    }

    // Inspect the pod spec for hostUsers.
    let host_users = kubectl(&[
        "get", "pod", &name, "-n", "openshell",
        "-o", "jsonpath={.spec.hostUsers}",
    ]).await;

    // Inspect capabilities on the agent container.
    let caps = kubectl(&[
        "get", "pod", &name, "-n", "openshell",
        "-o", "jsonpath={.spec.containers[?(@.name=='agent')].securityContext.capabilities.add}",
    ]).await;

    // Clean up.
    drop(child);
    delete_sandbox(&name).await;
    set_user_namespaces(false).await.ok();

    // Assert hostUsers is false.
    let host_users_val = host_users.expect("failed to get hostUsers from pod spec");
    assert_eq!(
        host_users_val.trim(), "false",
        "sandbox pod must have spec.hostUsers=false when user namespaces are enabled"
    );

    // Assert extra capabilities are present.
    let caps_val = caps.expect("failed to get capabilities from pod spec");
    for cap in ["SETUID", "SETGID", "DAC_READ_SEARCH"] {
        assert!(
            caps_val.contains(cap),
            "sandbox pod must include {cap} in capabilities when user namespaces are enabled, got: {caps_val}"
        );
    }
    for cap in ["SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYSLOG"] {
        assert!(
            caps_val.contains(cap),
            "sandbox pod must include {cap} in capabilities, got: {caps_val}"
        );
    }
}
