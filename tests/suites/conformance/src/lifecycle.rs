// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox lifecycle suite.
//!
//! These tests are adapted from the `sandbox-lifecycle` suite in
//! NVIDIA/OpenShell#4629 by Evan Lezar. Tests that need a driver with a
//! persistent workspace live in `persistent_workspace.rs`.

use std::time::Duration;

use testkit::sdk::{SandboxPhase, SandboxRestartPolicy};
use testkit::{Context, ResultExt as _, Sandbox, with_deadline};

/// A long-running sandbox becomes ready, runs a command with exec, and is gone
/// from get and list after delete.
#[testkit::test]
async fn long_running_exec_delete(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("lr")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    let marker = format!("openshell-e2e-{}", cx.run_id());
    sandbox
        .exec(["echo", marker.as_str()])
        .await?
        .expect_stdout(&format!("{marker}\n"))?;

    sandbox.delete().await?;
    sandbox.expect_absent().await
}

/// Longer than the supervisor's 30s startup recovery deadline.
const PAST_RECOVERY_DEADLINE: Duration = Duration::from_secs(31);
/// The exec's own timeout is the runner's two-minute kill, so fail sooner,
/// with a message that says which step hung.
const PAST_RECOVERY_EXEC_DEADLINE: Duration = Duration::from_mins(1);

/// An exec admitted before the startup recovery deadline expires keeps
/// running past it, and a new exec still works afterwards.
#[testkit::test]
async fn exec_outlives_startup_recovery_deadline(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("rd")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    let script = format!(
        "sleep {}; printf past-recovery-deadline",
        PAST_RECOVERY_DEADLINE.as_secs()
    );
    with_deadline(
        "the exec past the recovery deadline",
        PAST_RECOVERY_EXEC_DEADLINE,
        sandbox.exec(["sh", "-c", script.as_str()]),
    )
    .await?
    .expect_stdout("past-recovery-deadline")
    .context("the recovery deadline must not end an admitted exec")?;

    sandbox
        .exec(["printf", "fresh-exec"])
        .await?
        .expect_stdout("fresh-exec")
        .context("exec after the recovery deadline")?;
    Ok(())
}

/// Long enough that the workload is still handling TERM when sandbox shutdown
/// begins, and below the supervisor's 5s wait before it kills the workload.
const TERM_HANDLING_DELAY: Duration = Duration::from_secs(3);

/// Well below the 30s termination grace period that a shutdown hang waits out.
const DELETE_DEADLINE: Duration = Duration::from_secs(10);

/// Many workloads do not exit immediately on TERM, for example while they run
/// cleanup handlers. Deleting such a running sandbox should still complete
/// promptly, rather than waiting out the runtime's termination grace period.
//
// Unignore this when the supervisor half of #5025 lands: on Podman the
// supervisor container still waits out its stop timeout.
#[testkit::test]
#[ignore = "https://github.com/NVIDIA/OpenShell/issues/5025"]
async fn delete_is_prompt_when_workload_is_slow_to_handle_term(
    cx: &mut Context,
) -> testkit::Result {
    // `sleep & wait` rather than a foreground `sleep`: sh defers traps until a
    // foreground child exits, but `wait` returns on the signal.
    let script = format!(
        "trap 'sleep {}; exit 0' TERM; \
         touch /tmp/delayed-term-ready; \
         while :; do sleep 3600 & wait $!; done",
        TERM_HANDLING_DELAY.as_secs()
    );
    let sandbox = cx
        .sandbox("dt")
        .command(["sh", "-c", script.as_str()])
        .create_ready()
        .await?;

    // Ready alone does not prove that the workload has installed its trap.
    sandbox
        .poll_exec(
            "workload TERM handler readiness",
            Duration::from_secs(10),
            ["test", "-f", "/tmp/delayed-term-ready"],
            |output| output.exit_code == 0,
        )
        .await?;

    // Use one deadline starting before delete, not a fresh timeout per step.
    // Boundary containment may kill the workload before its handler finishes;
    // this asserts bounded deletion, not a graceful workload exit.
    with_deadline(
        &format!("deleting sandbox {}", sandbox.name()),
        DELETE_DEADLINE,
        async {
            sandbox.delete().await?;
            sandbox.expect_absent().await
        },
    )
    .await
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
    sandbox.expect_absent().await
}

/// A main command that exits during provisioning is reported as the
/// workload's result, not as a provisioning failure: the create succeeds and
/// the sandbox reaches Error with the command's exit code.
#[testkit::test]
async fn main_exit_during_provisioning_is_workload_result(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("pe")
        .command(["sh", "-c", "exit 11"])
        .restart_policy(SandboxRestartPolicy::Never)
        .create()
        .await?;

    let finished = sandbox.wait_finished().await?;
    testkit::ensure!(
        finished.phase == SandboxPhase::Error && finished.exit_code == Some(11),
        "sandbox finished in phase {:?} with exit code {:?}; expected Error with Some(11)",
        finished.phase,
        finished.exit_code
    );
    Ok(())
}

/// A main command that exits after the sandbox is Ready leaves its result:
/// exit 0 reaches Completed, and a non-zero exit reaches Error with that code.
#[testkit::test]
async fn main_exit_after_ready_sets_final_phase(cx: &mut Context) -> testkit::Result {
    const RELEASE_PATH: &str = "/sandbox/.openshell-main-release";
    let cases = [
        ("mz", 0, SandboxPhase::Completed),
        ("mn", 11, SandboxPhase::Error),
    ];

    // Create every sandbox before waiting, so they provision concurrently.
    let mut sandboxes = Vec::new();
    for (suffix, code, phase) in cases {
        let script =
            format!("while [ ! -e '{RELEASE_PATH}' ]; do sleep 0.05; done; sleep 1; exit {code}");
        let sandbox = cx
            .sandbox(suffix)
            .command(["sh", "-c", script.as_str()])
            .restart_policy(SandboxRestartPolicy::Never)
            .create()
            .await?;
        sandboxes.push((sandbox, code, phase));
    }

    for (sandbox, code, phase) in &sandboxes {
        sandbox.wait_ready().await?;
        sandbox.exec(["touch", RELEASE_PATH]).await?.success()?;
        let finished = sandbox.wait_finished().await?;
        testkit::ensure!(
            finished.phase == *phase && finished.exit_code == Some(*code),
            "main exiting {code} left sandbox {} in phase {:?} with exit code {:?}; expected {phase:?} with Some({code})",
            sandbox.name(),
            finished.phase,
            finished.exit_code
        );
    }
    Ok(())
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
    sandbox.expect_listed(SandboxPhase::Ready).await?;

    let marker = format!("openshell-e2e-{}", cx.run_id());
    sandbox
        .exec(["echo", marker.as_str()])
        .await?
        .expect_stdout(&format!("{marker}\n"))?;
    // The gateway's default image is OpenShell's Ubuntu base image.
    crate::image::expect_ubuntu(&sandbox).await?;

    sandbox.delete().await?;
    sandbox.expect_absent().await
}

/// A stopped sandbox rejects exec, accepts a second stop, and returns to
/// Ready when started.
#[testkit::test]
async fn restart_stopped_sandbox(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("rs")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;

    sandbox.stop().await?;
    let rejected = sandbox.exec(["true"]).await;
    testkit::ensure!(
        !matches!(&rejected, Ok(output) if output.exit_code == 0),
        "exec succeeded while the sandbox was stopped"
    );
    // Stop is idempotent.
    let again = sandbox.stop().await?;
    testkit::ensure!(
        again.phase == SandboxPhase::Stopped,
        "a second stop left the sandbox {:?}",
        again.phase
    );

    sandbox.start().await?;
    sandbox
        .exec(["echo", "started"])
        .await?
        .expect_stdout("started\n")
        .context("exec after start")?;
    Ok(())
}

/// A stopped sandbox can be deleted, and is then gone from get and list.
#[testkit::test]
async fn stopped_sandbox_can_be_deleted(cx: &mut Context) -> testkit::Result {
    let sandbox = cx
        .sandbox("sd")
        .command(["sleep", "infinity"])
        .create_ready()
        .await?;
    sandbox.stop().await?;
    sandbox.delete().await?;
    sandbox.expect_absent().await
}

/// Where the main command of [`canonical_main_environment`] records what it
/// sees.
const MAIN_ENV_PATH: &str = "/sandbox/.openshell-main-env";

/// Declared environment reaches both the main command and exec, with and
/// without a TTY. A TTY main command also gets the sandbox user's `HOME` and
/// `USER`, not the supervisor's, and a usable `TERM`.
#[testkit::test]
async fn canonical_main_environment(cx: &mut Context) -> testkit::Result {
    let declared = format!("present-{}", cx.run_id());
    let script = format!(
        "printf 'declared=%s\\nhome=%s\\nuser=%s\\nterm=%s\\n' \
         \"${{REPRO_SENTINEL:-missing}}\" \"$HOME\" \"$USER\" \"$TERM\" > '{MAIN_ENV_PATH}'; \
         exec sleep infinity"
    );

    let mut sandboxes = Vec::new();
    for (suffix, tty) in [("et", true), ("en", false)] {
        let sandbox = cx
            .sandbox(suffix)
            .command(["sh", "-c", script.as_str()])
            .spec(|spec| {
                spec.tty = tty;
                spec.environment
                    .insert("REPRO_SENTINEL".to_string(), declared.clone());
            })
            .create()
            .await?;
        sandboxes.push((sandbox, tty));
    }

    for (sandbox, tty) in &sandboxes {
        sandbox.wait_ready().await?;
        let main = main_environment(sandbox).await?;
        let field = |name: &str| main.get(name).map_or("", String::as_str);
        testkit::ensure!(
            field("declared") == declared,
            "the main command (tty {tty}) saw REPRO_SENTINEL={:?}; expected {declared:?}",
            field("declared")
        );

        sandbox
            .exec(["sh", "-c", "printf '%s' \"${REPRO_SENTINEL:-missing}\""])
            .await?
            .expect_stdout(&declared)
            .context(format!("REPRO_SENTINEL in exec (tty {tty})"))?;

        if *tty {
            testkit::ensure!(
                !field("home").is_empty() && field("home") != "/root",
                "the TTY main command inherited the supervisor's HOME: {main:?}"
            );
            testkit::ensure!(
                !field("user").is_empty(),
                "the TTY main command has no USER: {main:?}"
            );
            testkit::ensure!(
                !field("term").is_empty() && field("term") != "dumb",
                "the TTY main command has no usable TERM: {main:?}"
            );
        }
    }
    Ok(())
}

/// The `key=value` lines the main command wrote to [`MAIN_ENV_PATH`]. The
/// sandbox can be Ready before the main command writes them.
async fn main_environment(
    sandbox: &Sandbox,
) -> testkit::Result<std::collections::HashMap<String, String>> {
    let output = sandbox
        .poll_exec(
            &format!(
                "the main command of {} to record its environment",
                sandbox.name()
            ),
            Duration::from_secs(30),
            ["cat", MAIN_ENV_PATH],
            |output| output.exit_code == 0 && output.stdout.contains("term="),
        )
        .await?;
    Ok(output
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect())
}

/// How long the gateway may take to remove an ephemeral sandbox after its
/// main command exits. Both sandboxes are released before the test waits, so
/// their removals overlap.
const EPHEMERAL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);

/// A detached sandbox created with `--no-keep` is removed once its main
/// command exits, whether the command succeeds or fails.
///
/// This checks only what the gateway shows: get and list stop returning the
/// sandbox. Conformance can't see driver resources, so the check that the
/// driver removed its containers, pods or VM state stays in the legacy
/// `e2e/rust/tests/ephemeral_cleanup.rs` until the driver suites replace it.
#[testkit::test]
async fn detached_no_keep_sandbox_is_removed_after_main_exits(cx: &mut Context) -> testkit::Result {
    let mut sandboxes = Vec::new();
    for (suffix, code) in [("ez", 0), ("ef", 17)] {
        let builder = cx.cli_sandbox(suffix);
        let release_path = format!("/sandbox/.ephemeral-release-{}", builder.name());
        let script =
            format!("while [ ! -e '{release_path}' ]; do sleep 0.1; done; sleep 1; exit {code}");
        let sandbox = builder
            .args(["--no-keep"])
            .command(["sh", "-c", &script])
            .create()
            .await?;
        sandboxes.push((sandbox, release_path, code));
    }

    for (sandbox, release_path, _) in &sandboxes {
        sandbox.wait_ready().await?;
        sandbox
            .exec(["touch", release_path.as_str()])
            .await?
            .success()?;
    }
    for (sandbox, _, code) in &sandboxes {
        sandbox
            .wait_absent(EPHEMERAL_CLEANUP_TIMEOUT)
            .await
            .context(format!("ephemeral sandbox exited {code}"))?;
    }
    Ok(())
}
