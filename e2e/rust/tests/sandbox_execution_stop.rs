// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Execution preconditions through a real single-replica Kubernetes Gateway.
#![cfg(all(feature = "e2e-kubernetes", not(feature = "e2e-kubernetes-ha")))]

use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::sandbox::SandboxGuard;

async fn details(name: &str) -> serde_json::Value {
    let (output, code) = run_cli(&["sandbox", "get", name, "--output", "json"]).await;
    assert_eq!(code, 0, "get failed: {output}");
    serde_json::from_str(&output).expect("structured sandbox status")
}

async fn stop_execution(name: &str, execution: &str, succeeds: bool) {
    let (output, code) = run_cli(&["sandbox", "stop", name, "--execution-id", execution]).await;
    assert_eq!(code == 0, succeeds, "conditional stop: {output}");
    if succeeds {
        assert!(
            output.contains(execution),
            "receipt must identify the stopped execution: {output}"
        );
    } else {
        assert!(
            output.contains("execution has changed"),
            "must reject the stale target: {output}"
        );
    }
}

#[tokio::test]
async fn stale_execution_cannot_stop_restart_or_same_name_recreation() {
    let mut first = SandboxGuard::create_with_gateway_default(&[])
        .await
        .unwrap();
    let name = first.name.clone();
    let a = details(&name).await;
    let execution_a = a["execution_id"]
        .as_str()
        .expect("execution identity")
        .to_string();
    assert!(execution_a.starts_with("exec-v1:"));
    stop_execution(&name, &execution_a, true).await;
    wait_for_sandbox_phase(&name, "Stopped", Duration::from_secs(120))
        .await
        .unwrap();
    let (output, code) = run_cli(&["sandbox", "start", &name]).await;
    assert_eq!(code, 0, "start failed: {output}");
    wait_for_sandbox_phase(&name, "Ready", Duration::from_secs(120))
        .await
        .unwrap();
    let b = details(&name).await;
    assert_eq!(a["id"], b["id"], "stop/start retains the sandbox");
    assert!(
        a["host_key_fingerprint"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
    );
    assert_eq!(
        a["host_key_fingerprint"], b["host_key_fingerprint"],
        "SSH identity survives execution replacement"
    );
    let execution_b = b["execution_id"].as_str().unwrap().to_string();
    assert_ne!(
        execution_a, execution_b,
        "replacement has a fresh execution"
    );
    stop_execution(&name, &execution_a, false).await;
    assert_eq!(details(&name).await["phase"], "Ready");
    first
        .exec(&["true"])
        .await
        .expect("replacement stays usable");
    first.cleanup().await;

    tokio::time::timeout(Duration::from_secs(120), async {
        loop {
            let (_, code) = run_cli(&["sandbox", "get", &name, "--output", "json"]).await;
            if code != 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("deleted sandbox disappears");
    let mut replacement = SandboxGuard::create_with_gateway_default(&["--name", &name])
        .await
        .unwrap();
    let c = details(&name).await;
    assert_ne!(b["id"], c["id"], "recreation changes sandbox identity");
    assert_ne!(
        b["host_key_fingerprint"], c["host_key_fingerprint"],
        "recreation receives a new SSH identity"
    );
    stop_execution(&name, &execution_b, false).await;
    assert_eq!(details(&name).await["phase"], "Ready");
    replacement
        .exec(&["true"])
        .await
        .expect("same-name replacement stays usable");
    stop_execution(&name, c["execution_id"].as_str().unwrap(), true).await;
    wait_for_sandbox_phase(&name, "Stopped", Duration::from_secs(120))
        .await
        .unwrap();
    replacement.cleanup().await;
}
