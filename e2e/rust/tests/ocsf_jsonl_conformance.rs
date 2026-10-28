// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Supervisor OCSF JSONL must validate against the native OCSF schema.
//!
//! Unit tests cover the builders; this covers what production call sites
//! actually write. Records are copied out of the Podman supervisor container,
//! whose `/var/log` is a tmpfs that `podman cp` can read while it runs.

#![cfg(feature = "e2e-podman")]

use std::io::Write;
use std::time::Duration;

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::container::{ContainerEngine, ContainerHttpServer};
use openshell_e2e::harness::sandbox::SandboxGuard;
use openshell_ocsf::validation::{load_class_schema, validate_required_fields};
use serde_json::Value;
use tempfile::NamedTempFile;

/// Denied traffic: TCP to hosts the policy doesn't list (Network Activity)
/// and an HTTP request the L7 policy denies (HTTP Activity). 198.51.100.1 is
/// RFC 5737 TEST-NET-2 and never routes.
fn traffic(host: &str, port: u16) -> String {
    format!(
        r#"
import socket, urllib.request
for target in [("example.com", 80), ("example.com", 443), ("198.51.100.1", 80)]:
    try:
        socket.create_connection(target, timeout=5).close()
    except OSError:
        pass
try:
    urllib.request.urlopen(urllib.request.Request("http://{host}:{port}/allowed", data=b"x", method="POST"), timeout=10)
except Exception:
    pass
"#
    )
}

const HTTP_SERVER: &str = r#"from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
    def do_POST(self):
        self.send_response(200)
        self.end_headers()
    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
"#;

/// A policy whose only endpoint is the test server, with an L7 rule that
/// allows `GET /allowed`, so any other request is an HTTP Activity denial.
fn l7_policy(host: &str, port: u16) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp policy file");
    write!(
        file,
        r#"version: 1

filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]

landlock:
  compatibility: best_effort

process:
  run_as_user: sandbox
  run_as_group: sandbox

network_policies:
  ocsf_l7:
    name: ocsf_l7
    endpoints:
      - host: {host}
        port: {port}
        protocol: rest
        enforcement: enforce
        allowed_ips: ["10.0.0.0/8", "172.0.0.0/8", "192.168.0.0/16", "fc00::/7"]
        rules:
          - allow:
              method: GET
              path: /allowed
    binaries:
      - path: /usr/bin/python*
      - path: /usr/local/bin/python*
      - path: /sandbox/.uv/python/*/bin/python*
"#
    )
    .expect("write policy");
    file
}

/// Classes the traffic must produce: Network, HTTP and SSH Activity (the
/// SSH session that runs the traffic).
const REQUIRED_CLASSES: [u64; 3] = [4001, 4002, 4007];

fn class_schema_name(class_uid: u64) -> Option<&'static str> {
    Some(match class_uid {
        0 => "base_event",
        1007 => "process_activity",
        2004 => "detection_finding",
        3002 => "authentication",
        4001 => "network_activity",
        4002 => "http_activity",
        4007 => "ssh_activity",
        5019 => "device_config_state_change",
        6002 => "application_lifecycle",
        6003 => "api_activity",
        _ => return None,
    })
}

async fn set_sandbox_setting(sandbox: &str, key: &str, value: &str) {
    let (output, code) =
        run_cli(&["settings", "set", sandbox, "--key", key, "--value", value]).await;
    assert_eq!(code, 0, "settings set {key}={value} failed:\n{output}");
}

fn missing_classes(records: &[Value]) -> Vec<u64> {
    REQUIRED_CLASSES
        .into_iter()
        .filter(|class| !records.iter().any(|r| r["class_uid"] == *class))
        .collect()
}

/// Copy the supervisor's OCSF JSONL records for `sandbox`, or say why not.
fn supervisor_records(engine: &ContainerEngine, sandbox: &str) -> Result<Vec<Value>, String> {
    let filter = format!("label=openshell.ai/sandbox-name={sandbox}");
    let ps = engine
        .command()
        .args([
            "ps",
            "--filter",
            &filter,
            "--format",
            "{{index .Labels \"openshell.ai/sandbox-id\"}}",
        ])
        .output()
        .map_err(|e| format!("could not run ps: {e}"))?;
    if !ps.status.success() {
        return Err(format!(
            "ps --filter {filter} failed: {}",
            String::from_utf8_lossy(&ps.stderr)
        ));
    }
    let ids = String::from_utf8_lossy(&ps.stdout);
    let id = ids
        .lines()
        .map(str::trim)
        .find(|id| !id.is_empty())
        .ok_or_else(|| format!("no container matches {filter}"))?;

    let dir = tempfile::tempdir().map_err(|e| format!("temp dir: {e}"))?;
    let source = format!("openshell-supervisor-{id}:/var/log/.");
    let copied = engine
        .command()
        .args(["cp", &source, &dir.path().display().to_string()])
        .output()
        .map_err(|e| format!("could not run cp: {e}"))?;
    if !copied.status.success() {
        return Err(format!(
            "cp {source} failed: {}",
            String::from_utf8_lossy(&copied.stderr)
        ));
    }

    let mut records = Vec::new();
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir.path())
        .map_err(|e| format!("read copied logs: {e}"))?
        .flatten()
    {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("openshell-ocsf") {
            continue;
        }
        let text =
            std::fs::read_to_string(entry.path()).map_err(|e| format!("read {name}: {e}"))?;
        // The supervisor may be mid-write when the file is copied; a final
        // line without its newline is incomplete, not malformed.
        let complete = text.rfind('\n').map_or("", |end| &text[..end]);
        for line in complete.lines().filter(|line| !line.trim().is_empty()) {
            records.push(
                serde_json::from_str(line)
                    .map_err(|e| format!("{name}: invalid JSON line: {e}"))?,
            );
        }
        files.push(name);
    }
    if files.is_empty() {
        return Err(format!("no openshell-ocsf* files in {source}"));
    }
    Ok(records)
}

#[tokio::test]
async fn supervisor_jsonl_conforms_to_the_native_schema() {
    let engine = ContainerEngine::from_env().expect("container engine");
    let server = ContainerHttpServer::start_python("ocsf-l7.openshell.test", HTTP_SERVER)
        .await
        .expect("start test server");
    let policy = l7_policy(&server.host, server.port);
    let policy_path = policy.path().to_str().expect("UTF-8 policy path");
    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", policy_path, "--no-tty"],
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("sandbox create");
    let traffic = traffic(&server.host, server.port);
    set_sandbox_setting(&guard.name, "ocsf_json_enabled", "true").await;

    // Settings reach the supervisor on its next poll; generate traffic until
    // every required class appears.
    let mut records = Vec::new();
    let mut last_error = None;
    for _ in 0..12 {
        let _ = guard.exec(&["python3", "-c", &traffic]).await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        match supervisor_records(&engine, &guard.name) {
            Ok(found) => {
                records = found;
                last_error = None;
                if missing_classes(&records).is_empty() {
                    break;
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    guard.cleanup().await;

    let missing = missing_classes(&records);
    assert!(
        missing.is_empty(),
        "missing OCSF classes {missing:?} in {} records; last copy error: {}",
        records.len(),
        last_error.as_deref().unwrap_or("none")
    );
    let mut failures = Vec::new();
    for record in &records {
        assert_eq!(
            record["metadata"]["version"],
            openshell_ocsf::OCSF_VERSION,
            "record labelled {}; native validation needs ocsf_schema_version unset \
             for this sandbox and the gateway",
            record["metadata"]["version"]
        );
        let class_uid = record["class_uid"].as_u64().expect("class_uid");
        let Some(class) = class_schema_name(class_uid) else {
            failures.push(format!(
                "class_uid {class_uid} has no schema mapping in this test"
            ));
            continue;
        };
        let schema = load_class_schema(class);
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
