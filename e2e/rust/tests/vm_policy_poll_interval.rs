// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A VM sandbox loads a live policy change within the configured supervisor
//! poll interval.
//!
//! `e2e-vm.sh` sets `supervisor_policy_poll_interval_secs = 1`. With the
//! supervisor default of 10 s, `policy set --wait` returns anywhere up to
//! 10 s after the change; with 1 s every update must load well inside the
//! bound below.

#![cfg(feature = "e2e")]

use std::fmt::Write as _;
use std::io::Write;
use std::time::{Duration, Instant};

use openshell_e2e::harness::cli::run_cli;
use openshell_e2e::harness::sandbox::SandboxGuard;
use tempfile::NamedTempFile;

/// Generous for a 1 s poll plus CLI and gateway overhead, and below what a
/// 10 s poll delivers in most updates.
const LOAD_BOUND: Duration = Duration::from_secs(5);

/// Policy YAML allowing any binary to reach `host` on port 443, with the
/// filesystem paths of `live_policy_update.rs`.
fn write_policy(host: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("create temp policy file");
    let mut policy = String::from(
        "version: 1\n\nfilesystem_policy:\n  include_workdir: true\n  read_only:\n    - /bin\n    - /usr\n    - /lib\n    - /proc\n    - /dev/urandom\n    - /app\n    - /etc\n    - /var/log\n  read_write:\n    - /sandbox\n    - /tmp\n    - /dev/null\n\nlandlock:\n  compatibility: best_effort\n\nnetwork_policies:\n",
    );
    let _ = write!(
        policy,
        "  rule_0:\n    name: rule_0\n    endpoints:\n      - host: {host}\n        port: 443\n    binaries:\n      - path: \"/**\"\n"
    );
    file.write_all(policy.as_bytes())
        .expect("write temp policy file");
    file.flush().expect("flush temp policy file");
    file
}

#[tokio::test]
async fn vm_policy_change_loads_within_the_configured_poll_interval() {
    let initial = write_policy("initial.example.com");
    let initial_path = initial.path().to_str().expect("utf-8 path").to_string();
    let mut guard = SandboxGuard::create_keep_with_args(
        &["--policy", &initial_path, "--no-tty"],
        &["sh", "-c", "echo Ready && sleep infinity"],
        "Ready",
    )
    .await
    .expect("create keep sandbox");

    for host in ["one.example.com", "two.example.com", "three.example.com"] {
        let policy = write_policy(host);
        let path = policy.path().to_str().expect("utf-8 path").to_string();
        let started = Instant::now();
        let (output, code) = run_cli(&[
            "policy",
            "set",
            &guard.name,
            "--policy",
            &path,
            "--wait",
            "--timeout",
            "60",
        ])
        .await;
        let elapsed = started.elapsed();
        eprintln!("policy for {host} loaded in {elapsed:?}");
        assert_eq!(code, 0, "policy set for {host} failed:\n{output}");
        assert!(
            elapsed < LOAD_BOUND,
            "policy for {host} loaded after {elapsed:?}, expected under {LOAD_BOUND:?}:\n{output}"
        );
    }

    guard.cleanup().await;
}
