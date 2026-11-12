// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e")]

//! The other tests in this file moved to the testkit conformance and
//! `features/cli-attach` suites. This one stays until #5507 is fixed.

use std::time::Duration;

use openshell_e2e::harness::cli::{run_cli, wait_for_sandbox_exec_contains};
use openshell_e2e::harness::output::{extract_field, strip_ansi};
use openshell_e2e::harness::sandbox::{E2E_WORKLOAD_IMAGE, SandboxGuard, unique_sandbox_name};
use serial_test::serial;
use tokio::time::{Instant, sleep};

const SANDBOX_RESTART_TIMEOUT: Duration = Duration::from_secs(60);

fn normalize_output(output: &str) -> String {
    let stripped = strip_ansi(output).replace('\r', "");
    let mut cleaned = String::with_capacity(stripped.len());

    for ch in stripped.chars() {
        match ch {
            '\u{8}' => {
                cleaned.pop();
            }
            '\u{4}' => {}
            _ => cleaned.push(ch),
        }
    }

    cleaned
}

async fn sandbox_details(name: &str) -> String {
    let (details, exit_code) = run_cli(&["sandbox", "get", name]).await;
    let details = normalize_output(&details);
    assert_eq!(
        exit_code, 0,
        "sandbox get should succeed for {name}:\n{details}"
    );
    details
}

// The conformance suite has no counterpart for this test: on the VM driver the
// replacement never starts (https://github.com/NVIDIA/OpenShell/issues/5507),
// and the legacy lanes that run this file are Docker and Kubernetes.
#[tokio::test]
#[serial(sandbox_lifecycle)]
async fn on_failure_policy_replaces_runtime_and_preserves_workspace() {
    const SCRIPT: &str = r#"
marker=/sandbox/.openshell-restart-e2e
if [ -e "$marker" ]; then
  printf 'replacement-%s\n' "$(cat /proc/sys/kernel/random/uuid)" > /sandbox/replacement-run
  sleep 300
else
  touch "$marker"
  printf 'initial-%s\n' "$(cat /proc/sys/kernel/random/uuid)" > /sandbox/initial-run
  while [ ! -e /sandbox/.openshell-restart-release ]; do sleep 0.05; done
  exit 17
fi
"#;

    let mut sandbox = SandboxGuard::manage_existing(unique_sandbox_name());
    let (output, exit_code) = run_cli(&[
        "sandbox",
        "create",
        "--name",
        &sandbox.name,
        "--from",
        E2E_WORKLOAD_IMAGE,
        "--detach",
        "--restart-policy",
        "on-failure",
        "--",
        "sh",
        "-lc",
        SCRIPT,
    ])
    .await;
    assert_eq!(
        exit_code, 0,
        "create sandbox with OnFailure policy: {output}"
    );
    wait_for_sandbox_exec_contains(
        &sandbox.name,
        &["cat", "/sandbox/initial-run"],
        "initial-",
        SANDBOX_RESTART_TIMEOUT,
    )
    .await
    .expect("initial main process should write its workspace marker");

    let initial_details = sandbox_details(&sandbox.name).await;
    let initial_instance = extract_field(&initial_details, "Main process instance")
        .expect("initial main process instance");
    sandbox
        .exec(&["touch", "/sandbox/.openshell-restart-release"])
        .await
        .expect("release initial main process");

    let deadline = Instant::now() + SANDBOX_RESTART_TIMEOUT;
    let mut last_runs = Err("replacement is not ready".to_string());
    let final_details = loop {
        let details = sandbox_details(&sandbox.name).await;
        let replacement_instance = extract_field(&details, "Main process instance")
            .is_some_and(|instance| instance != "-" && instance != initial_instance);
        if details.contains("Phase: Ready")
            && extract_field(&details, "Restart count").as_deref() == Some("1")
            && replacement_instance
        {
            last_runs = sandbox
                .exec(&["cat", "/sandbox/initial-run", "/sandbox/replacement-run"])
                .await;
            if let Ok(runs) = &last_runs
                && runs.contains("initial-")
                && runs.contains("replacement-")
            {
                break details;
            }
        }
        assert!(
            Instant::now() < deadline,
            "sandbox did not complete its policy-driven restart within \
             {SANDBOX_RESTART_TIMEOUT:?}; last details:\n{details}\nworkspace: {last_runs:?}"
        );
        sleep(Duration::from_millis(250)).await;
    };

    assert!(
        final_details.contains("Restart policy: on-failure"),
        "restart policy should remain visible after replacement:\n{final_details}"
    );
    sandbox.cleanup().await;
}
