// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! VM-driver-specific assertions for the sandbox root filesystem.

use std::process::Stdio;
use std::time::Duration;

use openshell_e2e::harness::binary::openshell_cmd;
use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_phase};
use openshell_e2e::harness::output::strip_ansi;
use openshell_e2e::harness::sandbox::{SandboxGuard, unique_sandbox_name};

#[tokio::test]
async fn vm_overlay() {
    let mut sandbox = SandboxGuard::create_keep(
        &["sh", "-c", "echo vm-sandbox-ready; exec sleep infinity"],
        "vm-sandbox-ready",
    )
    .await
    .expect("sandbox create should start a durable main process");

    let script = concat!(
        "set -eu; ",
        "test \"$(stat -f -c %T /)\" = \"overlayfs\"; ",
        "printf \"overlay-write\\n\" > /sandbox/overlay-check; ",
        "test \"$(cat /sandbox/overlay-check)\" = \"overlay-write\"; ",
        "if [ -e /opt/openshell/tls/tls.key ]; then ",
        "test \"$(stat -c %a /opt/openshell/tls/tls.key)\" = \"600\"; ",
        "fi; ",
        "echo vm-overlay-ok",
    );

    let mut exec_cmd = openshell_cmd();
    exec_cmd
        .args(["sandbox", "exec", "--name", &sandbox.name, "--no-tty", "--"])
        .arg("sh")
        .arg("-lc")
        .arg(script)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let output = exec_cmd
        .output()
        .await
        .expect("failed to run VM overlay assertion");
    let combined = strip_ansi(&format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ));
    assert!(
        output.status.success() && combined.contains("vm-overlay-ok"),
        "VM overlay assertion failed (status {:?}):\n{combined}",
        output.status.code(),
    );

    sandbox.cleanup().await;
}

// VM stop terminates the guest without flushing its page cache. Flush this
// fixture before readiness so restart checks durable file content and ownership.
const IDENTITY_MAIN: &str = "set -eu; if ! test -f /sandbox/canonical-identity; then printf '%s:%s\\n' \"$(id -u)\" \"$(id -g)\" > /sandbox/canonical-identity; sync; fi; echo vm-identity-ready; exec sleep infinity";

fn identity_policy(user: &str, group: &str) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temporary identity policy");
    std::fs::write(
        file.path(),
        format!(
            r#"version: 1
filesystem_policy:
  include_workdir: true
  read_only: [/usr, /lib, /lib64, /proc, /etc, /dev/urandom]
  read_write: [/sandbox, /tmp, /dev/null]
landlock:
  compatibility: hard_requirement
process:
  run_as_user: "{user}"
  run_as_group: "{group}"
network_policies: {{}}
"#
        ),
    )
    .expect("write identity policy");
    file
}

async fn assert_workload_identity(sandbox: &SandboxGuard) -> (String, String) {
    let output = sandbox.exec(&[
        "sh", "-c",
        "set -eu; actual=$(id -u):$(id -g); canonical=$(cat /sandbox/canonical-identity); owner=$(stat -c %u:%g /sandbox/canonical-identity); printf 'exec=%s canonical=%s owner=%s\\n' \"$actual\" \"$canonical\" \"$owner\"; test \"$canonical\" = \"$actual\"; test \"$owner\" = \"$actual\"; printf 'identity=%s\\n' \"$actual\"",
    ]).await.expect("canonical and exec identities and file ownership agree");
    let clean = strip_ansi(&output);
    let pair = clean
        .lines()
        .find_map(|line| line.strip_prefix("identity="))
        .expect("observed workload identity");
    let (uid, gid) = pair.split_once(':').expect("UID:GID pair");
    let (status, code) = run_cli(&["sandbox", "get", &sandbox.name, "--output", "json"]).await;
    assert_eq!(code, 0, "{status}");
    let status: serde_json::Value =
        serde_json::from_str(&strip_ansi(&status)).expect("sandbox status JSON");
    assert!(
        status["conditions"]
            .as_array()
            .expect("conditions")
            .iter()
            .any(|condition| {
                condition["type"] == "WorkloadIdentity"
                    && condition["message"] == format!("Resolved workload UID:GID is {pair}")
            }),
        "status must report observed workload identity: {status}"
    );
    (uid.to_string(), gid.to_string())
}

#[tokio::test]
async fn vm_identity_matches_status_and_rejects_conflicts() {
    // Use observed defaults so the test also works with configured driver IDs.
    // The canonical process writes a file before signaling readiness; exec
    // verifies its content and ownership independently of the status report.
    let default_policy = identity_policy("", "");
    let mut sandbox = SandboxGuard::create_keep_with_args(
        &[
            "--policy",
            default_policy.path().to_str().unwrap(),
            "--no-tty",
        ],
        &["sh", "-c", IDENTITY_MAIN],
        "vm-identity-ready",
    )
    .await
    .expect("omitted selectors use driver identity");
    let (uid, gid) = assert_workload_identity(&sandbox).await;
    let original = sandbox
        .exec(&["stat", "-c", "%u:%g", "/sandbox/canonical-identity"])
        .await
        .unwrap();
    let (output, code) = run_cli(&["sandbox", "stop", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    wait_for_sandbox_phase(&sandbox.name, "Stopped", Duration::from_secs(60))
        .await
        .unwrap();
    let (output, code) = run_cli(&["sandbox", "start", &sandbox.name]).await;
    assert_eq!(code, 0, "{output}");
    wait_for_sandbox_phase(&sandbox.name, "Ready", Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(
        assert_workload_identity(&sandbox).await,
        (uid.clone(), gid.clone())
    );
    let restored = sandbox
        .exec(&["stat", "-c", "%u:%g", "/sandbox/canonical-identity"])
        .await
        .unwrap();
    assert_eq!(
        strip_ansi(&restored),
        strip_ansi(&original),
        "restart must retain the owned overlay file"
    );
    sandbox.cleanup().await;

    for (user, group) in [
        (uid.as_str(), ""),
        ("", gid.as_str()),
        ("sandbox", "sandbox"),
    ] {
        let policy = identity_policy(user, group);
        let mut matching = SandboxGuard::create_keep_with_args(
            &["--policy", policy.path().to_str().unwrap(), "--no-tty"],
            &["sh", "-c", IDENTITY_MAIN],
            "vm-identity-ready",
        )
        .await
        .expect("matching numeric or symbolic selector");
        assert_eq!(
            assert_workload_identity(&matching).await,
            (uid.clone(), gid.clone())
        );
        matching.cleanup().await;
    }

    let wrong_uid = if uid == "10000" { "10001" } else { "10000" };
    let wrong_gid = if gid == "10000" { "10001" } else { "10000" };
    for (user, group, field) in [
        (wrong_uid, "", "run_as_user"),
        ("", wrong_gid, "run_as_group"),
    ] {
        let policy = identity_policy(user, group);
        let name = unique_sandbox_name();
        let mut cleanup = SandboxGuard::manage_existing(name.clone());
        let result = SandboxGuard::create(&[
            "--name",
            &name,
            "--policy",
            policy.path().to_str().unwrap(),
            "--no-tty",
        ])
        .await;
        let error = match result {
            Ok(mut launched) => {
                launched.cleanup().await;
                panic!("conflicting VM identity reached Ready");
            }
            Err(error) => error,
        };
        assert!(
            error.contains(field) && error.contains(&format!("{uid}:{gid}")),
            "rejection must name selector and resolved identity: {error}"
        );
        cleanup.cleanup().await;
    }
}
