// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor OCSF JSONL must validate against the native OCSF schema.
//!
//! Unit tests cover the builders; this covers what production call sites
//! actually write. Records are copied out of the Podman supervisor container,
//! whose `/var/log` is a tmpfs that `podman cp` can read while it runs.

#![cfg(feature = "e2e-podman")]

use std::time::Duration;

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::container::ContainerEngine;
use openshell_e2e::harness::sandbox::SandboxGuard;
use openshell_ocsf::validation::{load_class_schema_for_version, validate_required_fields};
use serde_json::Value;

/// Denied connections: a proxied name, a TLS port, and a direct address.
/// 198.51.100.1 is RFC 5737 TEST-NET-2 and never routes.
const TRAFFIC: &str = r#"
import socket
for host, port in [("example.com", 80), ("example.com", 443), ("198.51.100.1", 80)]:
    try:
        socket.create_connection((host, port), timeout=5).close()
    except OSError:
        pass
"#;

fn class_schema_name(class_uid: u64) -> &'static str {
    match class_uid {
        1007 => "process_activity",
        2004 => "detection_finding",
        3002 => "authentication",
        4001 => "network_activity",
        4002 => "http_activity",
        4007 => "ssh_activity",
        5019 => "device_config_state_change",
        6002 => "application_lifecycle",
        6003 => "api_activity",
        _ => "base_event",
    }
}

async fn set_sandbox_setting(sandbox: &str, key: &str, value: &str) {
    let (output, code) =
        run_cli(&["settings", "set", sandbox, "--key", key, "--value", value]).await;
    assert_eq!(code, 0, "settings set {key}={value} failed:\n{output}");
}

/// Copy the supervisor's OCSF JSONL records for `sandbox`.
fn supervisor_records(engine: &ContainerEngine, sandbox: &str) -> Vec<Value> {
    let ids = engine
        .command()
        .args([
            "ps",
            "--filter",
            &format!("label=openshell.ai/sandbox-name={sandbox}"),
            "--format",
            "{{index .Labels \"openshell.ai/sandbox-id\"}}",
        ])
        .output()
        .expect("list sandbox containers");
    let ids = String::from_utf8_lossy(&ids.stdout);
    let Some(id) = ids.lines().map(str::trim).find(|id| !id.is_empty()) else {
        return Vec::new();
    };

    let dir = tempfile::tempdir().expect("temp dir");
    let copied = engine
        .command()
        .args([
            "cp",
            &format!("openshell-supervisor-{id}:/var/log/."),
            &dir.path().display().to_string(),
        ])
        .output()
        .expect("copy supervisor logs");
    if !copied.status.success() {
        return Vec::new();
    }

    let mut records = Vec::new();
    for entry in std::fs::read_dir(dir.path())
        .expect("read copied logs")
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("openshell-ocsf") {
            continue;
        }
        let text = std::fs::read_to_string(entry.path()).expect("read JSONL");
        records.extend(
            text.lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| serde_json::from_str(line).expect("each JSONL line is JSON")),
        );
    }
    records
}

#[tokio::test]
async fn supervisor_jsonl_conforms_to_the_native_schema() {
    let engine = ContainerEngine::from_env().expect("container engine");
    let mut guard = SandboxGuard::create_detached_main(&["sleep", "600"])
        .await
        .expect("sandbox create");
    set_sandbox_setting(&guard.name, "ocsf_json_enabled", "true").await;

    // Settings reach the supervisor on its next poll; generate traffic until
    // network decisions appear alongside the startup records.
    let mut records = Vec::new();
    for _ in 0..12 {
        let _ = guard.exec(&["python3", "-c", TRAFFIC]).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        records = supervisor_records(&engine, &guard.name);
        if records.iter().any(|r| r["class_uid"] == 4001) {
            break;
        }
    }
    guard.cleanup().await;

    assert!(
        records.iter().any(|r| r["class_uid"] == 4001),
        "expected network activity records, got {} records",
        records.len()
    );
    let mut failures = Vec::new();
    for record in &records {
        assert_eq!(
            record["metadata"]["version"],
            openshell_ocsf::OCSF_VERSION,
            "unexpected version on {record}"
        );
        let class = class_schema_name(record["class_uid"].as_u64().expect("class_uid"));
        let schema = load_class_schema_for_version(openshell_ocsf::OCSF_VERSION, class);
        if let Err(panic) = std::panic::catch_unwind(|| validate_required_fields(record, &schema)) {
            let reason = panic.downcast_ref::<String>().cloned().unwrap_or_default();
            failures.push(format!(
                "{} \"{}\": {reason}",
                record["class_name"],
                record["message"].as_str().unwrap_or_default()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "non-conformant records:\n{}",
        failures.join("\n")
    );
}
