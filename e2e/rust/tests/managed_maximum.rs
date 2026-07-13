// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use openshell_e2e::harness::binary::{openshell_bin, openshell_cmd};
use openshell_e2e::harness::cli::sandbox_names;
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::SandboxGuard;
use serde_json::Value;
use tempfile::NamedTempFile;
use tokio::time::sleep;

struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        for args in [
            vec!["policy", "maximum", "delete", "--yes"],
            vec![
                "settings",
                "delete",
                "--global",
                "--key",
                "agent_policy_proposals_enabled",
                "--yes",
            ],
        ] {
            let _ = Command::new(openshell_bin())
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

async fn cli(args: &[&str]) -> (bool, String) {
    let output = openshell_cmd()
        .args(args)
        .output()
        .await
        .expect("spawn openshell");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), strip_ansi(&combined))
}

fn temp_policy(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create policy file");
    file.write_all(contents.as_bytes()).expect("write policy");
    file.flush().expect("flush policy");
    file
}

fn json_from_exec(output: &str) -> Value {
    let json = output
        .lines()
        .find(|line| line.trim_start().starts_with('{'))
        .unwrap_or_else(|| panic!("sandbox output did not contain JSON:\n{output}"));
    serde_json::from_str(json).expect("parse policy.local response")
}

async fn submit(sandbox: &SandboxGuard, method: &str, suffix: &str) -> Value {
    let script = r#"import json, sys, urllib.request, urllib.error
method, suffix = sys.argv[1], sys.argv[2]
payload = {
  "intent_summary": "managed maximum e2e",
  "operations": [{"addRule": {
    "ruleName": f"managed_{suffix}",
    "rule": {
      "name": f"managed_{suffix}",
      "endpoints": [{
        "host": "api.github.com",
        "port": 443,
        "protocol": "rest",
        "enforcement": "enforce",
        "rules": [{"allow": {"method": method, "path": f"/repos/acme/{suffix}"}}]
      }],
      "binaries": [{"path": "/usr/bin/curl"}]
    }
  }}]
}
request = urllib.request.Request(
  "http://policy.local/v1/proposals",
  data=json.dumps(payload).encode(),
  headers={"Content-Type": "application/json"},
  method="POST")
try:
  response = urllib.request.urlopen(request)
  print(response.read().decode())
except urllib.error.HTTPError as error:
  print(error.read().decode())
  raise
"#;
    let invocation = format!("exec({script:?})");
    let output = sandbox
        .exec(&["python3", "-c", &invocation, method, suffix])
        .await
        .expect("submit policy.local proposal");
    json_from_exec(&output)
}

async fn wait_for_proposal(sandbox: &SandboxGuard, chunk_id: &str) -> Value {
    let script = r#"import sys, urllib.request
url = f"http://policy.local/v1/proposals/{sys.argv[1]}/wait?timeout=30"
print(urllib.request.urlopen(url).read().decode())
"#;
    let invocation = format!("exec({script:?})");
    let output = sandbox
        .exec(&["python3", "-c", &invocation, chunk_id])
        .await
        .expect("wait for proposal");
    json_from_exec(&output)
}

async fn wait_for_rule_status(sandbox_name: &str, chunk_id: &str, status: &str) {
    let start = Instant::now();
    loop {
        let (success, output) = cli(&["rule", "get", sandbox_name, "--status", status]).await;
        if success && output.contains(chunk_id) {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "timed out waiting for chunk {chunk_id} to become {status}:\n{output}"
        );
        sleep(Duration::from_secs(1)).await;
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn managed_maximum_auto_ask_reject_and_reload() {
    assert!(
        sandbox_names().await.expect("list sandboxes").is_empty(),
        "managed maximum e2e requires the isolated gateway to start without sandboxes"
    );
    let _cleanup = Cleanup;

    let maximum = temp_policy(include_str!(
        "../../../examples/managed-maximum-policies/github-rest.yaml"
    ));
    let base = temp_policy(
        r"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /proc, /dev/urandom, /app, /etc, /var/log]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: best_effort
process:
  run_as_user: sandbox
  run_as_group: sandbox
network_policies: {}
",
    );
    let maximum_path = maximum.path().to_str().expect("maximum path is utf-8");
    let base_path = base.path().to_str().expect("base path is utf-8");

    let (success, output) = cli(&[
        "settings",
        "set",
        "--global",
        "--key",
        "agent_policy_proposals_enabled",
        "--value",
        "true",
        "--yes",
    ])
    .await;
    assert!(success, "enable policy advisor:\n{output}");

    let (success, output) =
        cli(&["policy", "maximum", "set", "--policy", maximum_path, "--yes"]).await;
    assert!(success, "set managed maximum:\n{output}");
    assert!(output.contains("github-read-auto-write-review@1"));
    println!("managed maximum: configured github-read-auto-write-review@1");

    let sandbox_name = format!("managed-maximum-{}", std::process::id());
    let mut sandbox = SandboxGuard::create(&[
        "--name",
        &sandbox_name,
        "--policy",
        base_path,
        "--permission-mode",
        "auto",
        "--no-tty",
        "--",
        "sh",
        "-c",
        "echo Ready",
    ])
    .await
    .expect("create managed sandbox");
    assert!(
        strip_ansi(&sandbox.create_output).contains("Permission mode: auto (managed)"),
        "sandbox create did not confirm the managed permission mode:\n{}",
        sandbox.create_output
    );
    println!("sandbox UX: confirmed permission mode auto (managed)");

    let read = submit(&sandbox, "GET", "read").await;
    let read_id = read["accepted_chunk_ids"][0]
        .as_str()
        .expect("read proposal id");
    wait_for_rule_status(&sandbox.name, read_id, "approved").await;
    let read_wait = wait_for_proposal(&sandbox, read_id).await;
    assert_eq!(read_wait["status"], "approved");
    assert_eq!(read_wait["policy_reloaded"], true);
    println!("GET proposal: auto-approved and live policy reloaded");

    let write = submit(&sandbox, "POST", "write").await;
    let write_id = write["accepted_chunk_ids"][0]
        .as_str()
        .expect("write proposal id");
    wait_for_rule_status(&sandbox.name, write_id, "pending").await;
    let (success, output) = cli(&[
        "rule",
        "approve",
        &sandbox.name,
        "--chunk-id",
        write_id,
    ])
    .await;
    assert!(success, "approve reviewed write:\n{output}");
    let write_wait = wait_for_proposal(&sandbox, write_id).await;
    assert_eq!(write_wait["status"], "approved");
    assert_eq!(write_wait["policy_reloaded"], true);
    println!("POST proposal: held for review, approved, and live policy reloaded");

    let denied = submit(&sandbox, "DELETE", "delete").await;
    assert_eq!(denied["accepted_chunks"], 0);
    assert_eq!(denied["rejected_chunks"], 1);
    assert!(denied["rejection_reasons"][0]
        .as_str()
        .is_some_and(|reason| reason.contains("maximum=github-read-auto-write-review@1")));
    println!("DELETE proposal: rejected by the managed maximum");

    let (success, logs) = cli(&[
        "logs",
        &sandbox.name,
        "--source",
        "gateway",
        "--since",
        "10m",
    ])
    .await;
    assert!(success, "read gateway logs:\n{logs}");
    assert!(logs.contains("managed admission"), "missing managed audit event:\n{logs}");
    println!("audit: managed admission event visible in gateway logs");

    sandbox.cleanup().await;
    let (success, output) = cli(&["policy", "maximum", "delete", "--yes"]).await;
    assert!(success, "delete managed maximum:\n{output}");
    println!("cleanup: sandbox and managed maximum deleted");
}
