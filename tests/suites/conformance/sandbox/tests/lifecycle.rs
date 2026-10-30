// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle suite.
//!
//! These tests are adapted from the `sandbox-lifecycle` suite in
//! NVIDIA/OpenShell#4629 by Evan Lezar. Tests that need a driver with a
//! persistent workspace live in `persistent_workspace.rs`.

use testkit::Context;
use testkit::sdk::{SandboxPhase, SandboxRestartPolicy};

/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("lr")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    let marker = format!("openshell-e2e-{}", cx.run_id());
    let output = sandbox.exec(["echo", marker.as_str()]).await?;
    testkit::ensure!(
        output.exit_code == 0,
        "exec exited with {}; stderr: {}",
        output.exit_code,
        output.stderr
    );
    testkit::ensure!(
        output.stdout == format!("{marker}\n"),
        "exec stdout was {:?}; expected {:?}",
        output.stdout,
        format!("{marker}\n")
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}

/// A sandbox whose main command exits 0, with restart policy Never, reaches
/// Completed with exit code 0 and is not restarted. It is gone from get and
/// list after delete.
#[testkit::test]
async fn run_to_completion_exit_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("rtc")
        .command(["sh", "-c", "exit 0"])
        .restart_policy(SandboxRestartPolicy::Never)
        .create()
        .await?;

    let finished = sandbox.wait_finished().await?;
    testkit::ensure!(
        finished.phase == SandboxPhase::Completed,
        "sandbox finished in phase {:?} with exit code {:?}; expected Completed",
        finished.phase,
        finished.exit_code
    );
    testkit::ensure!(
        finished.exit_code == Some(0),
        "exit code was {:?}; expected Some(0)",
        finished.exit_code
    );
    testkit::ensure!(
        finished.restart_count == 0,
        "restart count was {}; expected 0",
        finished.restart_count
    );

    // Completed is final under Never: a later read must not show a restart.
    let again = sandbox.get().await?;
    testkit::ensure!(
        again.phase == SandboxPhase::Completed && again.restart_count == 0,
        "sandbox left Completed: phase {:?}, restart count {}",
        again.phase,
        again.restart_count
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}

/// A sandbox created with the gateway's default command becomes Ready, is
/// listed as Ready, runs a command with exec, and is gone after delete.
#[testkit::test]
async fn default_command_sandbox_is_listed_ready(cx: &mut Context) -> testkit::Result {
    let sandbox = cx.sandbox("dc").create().await?;
    let ready = sandbox.wait_ready().await?;
    testkit::ensure!(
        ready.name == sandbox.name(),
        "get returned sandbox {:?}; expected {:?}",
        ready.name,
        sandbox.name()
    );
    cx.expect_listed(&sandbox, SandboxPhase::Ready).await?;

    let marker = format!("openshell-e2e-{}", cx.run_id());
    let output = sandbox.exec(["echo", marker.as_str()]).await?;
    testkit::ensure!(
        output.exit_code == 0 && output.stdout == format!("{marker}\n"),
        "exec exited {} with stdout {:?}; stderr: {}",
        output.exit_code,
        output.stdout,
        output.stderr
    );

    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}

/// A stopped sandbox rejects exec, accepts a second stop, and returns to
/// Ready when started.
#[testkit::test]
async fn restart_stopped_sandbox(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("rs")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;

    sandbox.stop().await?;
    match sandbox.exec(["true"]).await {
        Err(_) => {}
        Ok(output) => testkit::ensure!(
            output.exit_code != 0,
            "exec succeeded while the sandbox was stopped"
        ),
    }
    // Stop is idempotent.
    let again = sandbox.stop().await?;
    testkit::ensure!(
        again.phase == SandboxPhase::Stopped,
        "a second stop left the sandbox {:?}",
        again.phase
    );

    sandbox.start().await?;
    let output = sandbox.exec(["echo", "started"]).await?;
    testkit::ensure!(
        output.exit_code == 0 && output.stdout == "started\n",
        "exec after start exited {} with stdout {:?}; stderr: {}",
        output.exit_code,
        output.stdout,
        output.stderr
    );
    Ok(())
}

/// A stopped sandbox can be deleted, and is then gone from get and list.
#[testkit::test]
async fn stopped_sandbox_can_be_deleted(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("sd")
        .command(["sleep", "infinity"])
        .create()
        .await?;
    sandbox.wait_ready().await?;
    sandbox.stop().await?;
    sandbox.delete().await?;
    cx.expect_absent(&sandbox).await
}
