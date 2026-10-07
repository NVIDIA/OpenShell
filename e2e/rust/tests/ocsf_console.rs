// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-docker")]

//! Full OCSF collection through supervisor stderr, without filesystem access.

use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tokio::process::Command;
use tokio::time::{Instant, sleep};

async fn cli(args: &[&str]) -> String {
    let output = openshell_cmd().args(args).output().await.unwrap();
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

async fn docker(args: &[&str]) -> (String, String) {
    let output = Command::new("docker").args(args).output().await.unwrap();
    assert!(
        output.status.success(),
        "Docker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn json_records(stderr: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter_map(|line| {
            let (_, payload) = line.split_once(" OCSF-JSON ")?;
            assert!(!payload.contains('\x1b'));
            Some(serde_json::from_str(payload).expect("complete JSON record on one line"))
        })
        .collect()
}

#[tokio::test]
async fn network_events_are_json_on_supervisor_stderr_only() {
    let mut sandbox = SandboxGuard::create(&["--from", "nvcr.io/nvidia/base/ubuntu:24.04"])
        .await
        .expect("create sandbox");
    let filter = format!("label=openshell.ai/sandbox-name={}", sandbox.name);
    let (containers, _) = docker(&[
        "ps",
        "-q",
        "--filter",
        &filter,
        "--filter",
        "label=openshell.ai/isolation-role=supervisor",
    ])
    .await;
    let ids: Vec<_> = containers.lines().collect();
    assert_eq!(ids.len(), 1, "expected one supervisor: {containers}");
    let supervisor = ids[0];
    let (_, before) = docker(&["logs", supervisor]).await;
    assert!(json_records(&before).is_empty(), "JSON must be opt-in");

    cli(&[
        "settings",
        "set",
        &sandbox.name,
        "--key",
        "ocsf_json_enabled",
        "--value",
        "true",
    ])
    .await;
    let started = Instant::now();
    let records = loop {
        cli(&[
            "sandbox",
            "exec",
            &sandbox.name,
            "--timeout",
            "10",
            "--",
            "bash",
            "-c",
            "echo > /dev/tcp/1.1.1.1/443 || true",
        ])
        .await;
        let (stdout, stderr) = docker(&["logs", supervisor]).await;
        assert!(
            !stdout.contains(" OCSF-JSON "),
            "audit JSON should be on stderr"
        );
        let records = json_records(&stderr);
        if records.iter().any(|record| {
            record["class_uid"] == 4001
                && record["dst_endpoint"]["port"] == 443
                && record["action"] == "Denied"
        }) {
            assert!(
                stderr.contains(" OCSF NET:OPEN "),
                "shorthand remains available"
            );
            break records;
        }
        assert!(
            started.elapsed() < Duration::from_secs(40),
            "no JSON network denial in stderr: {stderr}"
        );
        sleep(Duration::from_secs(1)).await;
    };
    for record in records {
        assert_eq!(record["metadata"]["version"], "1.8.0");
        assert!(
            record["metadata"]["uid"]
                .as_str()
                .is_some_and(|uid| !uid.is_empty())
        );
        assert_eq!(record["container"]["name"], sandbox.name);
    }
    // Allow the existing best-effort push batch to reach the gateway.
    sleep(Duration::from_secs(2)).await;
    let gateway_logs = cli(&["logs", &sandbox.name, "--source", "sandbox", "-n", "200"]).await;
    assert!(gateway_logs.contains("NET:OPEN"));
    assert!(
        !gateway_logs.contains("OCSF-JSON"),
        "gateway stream must remain unchanged"
    );
    sandbox.cleanup().await;
}
