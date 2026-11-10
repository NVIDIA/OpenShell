// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Attaching to a sandbox's main process with `sandbox connect`: one input
//! owner, read-only viewers, retained history on reconnect, and the main
//! process's exit code.
//!
//! Ported from `e2e/rust/tests/sandbox_lifecycle.rs`. The CLI-side transport
//! recovery and signal tests are in `tests/suites/features/cli-attach`.

use std::process::Stdio;
use std::time::Duration;

use testkit::sdk::SandboxPhase;
use testkit::{CliChild, Context, ResultExt as _};

/// How long an attachment may take to show output.
const ATTACH_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the CLI treats a new attachment as still connecting. A failure
/// after that is a transport failure it may recover from.
const ESTABLISHED: Duration = Duration::from_secs(3);

/// A main process that prints a numbered line every 0.2 seconds and echoes
/// each line of its input, each with its PID.
const ECHO_MAIN: &str = r#"trap 'kill "$writer" 2>/dev/null || true' EXIT; (n=1; while true; do printf 'main_pid=%s sequence=%04d\n' "$$" "$n"; n=$((n + 1)); sleep 0.2; done) & writer=$!; while IFS= read -r line; do printf 'main_pid=%s input=%s\n' "$$" "$line"; done"#;
const FIRST_RECORD: &str = "sequence=0001";

/// The first `sandbox connect` owns the main process's input. A second one
/// is told it is read-only, still sees output, and exits 0 on Ctrl-C without
/// taking input from the owner. After the owner disconnects, a new
/// attachment takes over input and replays the retained output from the
/// first record, all from the same process. Stopping and starting the
/// sandbox works while it is attached.
#[testkit::test]
async fn attach_reconnect_replays_history_for_the_same_main_process(
    cx: &mut Context,
) -> testkit::Result {
    let sandbox = cx
        .sandbox("rc")
        .command(["sh", "-lc", ECHO_MAIN])
        .create_ready()
        .await?;
    let connect = ["sandbox", "connect", sandbox.name()];

    let mut owner = cx.cli_spawn(connect)?;
    let owner_line = owner.stdout_line(ATTACH_TIMEOUT).await?;
    let main_pid = owner_line
        .split_whitespace()
        .find_map(|field| field.strip_prefix("main_pid="))
        .ok_or_else(|| testkit::Error::msg(format!("unexpected owner output {owner_line:?}")))?
        .to_string();

    let mut viewer = cx.cli_spawn(connect)?;
    let warning = viewer
        .stderr_until(ATTACH_TIMEOUT, |line| {
            line.contains("already has an input owner")
        })
        .await?
        .pop()
        .unwrap_or_default();
    testkit::ensure!(
        warning.contains("read-only"),
        "a second attachment was not told it is read-only: {warning:?}"
    );
    let viewer_line = viewer.stdout_line(ATTACH_TIMEOUT).await?;
    testkit::ensure!(
        viewer_line.contains("main_pid="),
        "a read-only attachment did not see output: {viewer_line:?}"
    );
    viewer
        .write_stdin(b"\x03")
        .await
        .context("send Ctrl-C to the viewer")?;
    let code = viewer.wait(ATTACH_TIMEOUT).await?;
    testkit::ensure!(code == 0, "the viewer exited with {code} on Ctrl-C");

    owner
        .write_stdin(b"owner-after-viewer-exit\n")
        .await
        .context("send input after the viewer exits")?;
    owner
        .stdout_until(ATTACH_TIMEOUT, |line| {
            line.contains("input=owner-after-viewer-exit")
        })
        .await
        .context("the owner keeps its input after the viewer exits")?;
    owner.kill().await?;

    let (mut reconnect, replay) = reconnect_with_input(cx, sandbox.name()).await?;
    testkit::ensure!(
        replay.iter().any(|line| line.contains(FIRST_RECORD)),
        "reconnect did not replay the retained history from {FIRST_RECORD}: {replay:?}"
    );
    testkit::ensure!(
        replay
            .iter()
            .all(|line| line.contains(&format!("main_pid={main_pid}"))),
        "reconnect shows a process other than {main_pid}: {replay:?}"
    );
    testkit::ensure!(
        replay.iter().any(|line| !line.contains(FIRST_RECORD)),
        "reconnect shows nothing beyond the first record: {replay:?}"
    );

    sandbox.stop().await?;
    testkit::ensure!(
        sandbox.get().await?.phase == SandboxPhase::Stopped,
        "sandbox {} is not Stopped",
        sandbox.name()
    );
    sandbox.start().await?;
    reconnect.kill().await
}

/// A main process that exits 255 after the attachment is established ends
/// `sandbox connect` with 255. The CLI doesn't mistake it for a lost SSH
/// transport, which also exits 255, and reconnect.
#[testkit::test]
async fn attach_main_exit_255_is_not_retried_as_transport_failure(
    cx: &mut Context,
) -> testkit::Result {
    const READY: &str = "exit-255-ready";
    const RELEASE: &str = "/sandbox/.openshell-exit-255-release";
    let script = format!("echo {READY}; while [ ! -e '{RELEASE}' ]; do sleep 0.05; done; exit 255");
    let sandbox = cx
        .sandbox("x255")
        .command(["sh", "-c", &script])
        .create_ready()
        .await?;

    let mut connect =
        cx.cli_spawn_with_stdin(["sandbox", "connect", sandbox.name()], Stdio::null())?;
    connect
        .stdout_until(ATTACH_TIMEOUT, |line| line.contains(READY))
        .await?;
    // Stay attached past the CLI's setup window, so a 255 would count as an
    // established transport failure.
    tokio::time::sleep(ESTABLISHED).await;
    let release = sandbox.exec(["touch", RELEASE]).await?;
    testkit::ensure!(
        release.exit_code == 0,
        "release the main process: {}",
        release.stderr.trim()
    );

    let code = connect
        .wait(Duration::from_secs(10))
        .await
        .context("a main exit of 255 must not start transport recovery")?;
    testkit::ensure!(
        code == 255,
        "`{}` exited with {code}; expected the main process's 255",
        connect.command()
    );
    Ok(())
}

/// Attach until one attachment takes over input, which it can only do once
/// the gateway has released the previous owner. Returns the attachment and
/// the output lines it showed up to its own input.
async fn reconnect_with_input(
    cx: &Context,
    name: &str,
) -> testkit::Result<(CliChild, Vec<String>)> {
    const DEADLINE: Duration = Duration::from_secs(30);
    let deadline = tokio::time::Instant::now() + DEADLINE;
    for attempt in 1.. {
        let token = format!("reconnect-{attempt}");
        let mut candidate = cx.cli_spawn(["sandbox", "connect", name])?;
        candidate
            .write_stdin(format!("{token}\n").as_bytes())
            .await
            .context("send reconnect input")?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let read = candidate
            .stdout_until(Duration::from_secs(2).min(remaining), |line| {
                line.contains(&format!("input={token}"))
            })
            .await;
        if let Ok(lines) = read {
            let replay = lines
                .into_iter()
                .filter(|line| line.contains("main_pid="))
                .collect();
            return Ok((candidate, replay));
        }
        candidate.kill().await?;
        testkit::ensure!(
            tokio::time::Instant::now() < deadline,
            "no reconnect to sandbox {name} took over input within {DEADLINE:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    unreachable!("the attempts are unbounded")
}
