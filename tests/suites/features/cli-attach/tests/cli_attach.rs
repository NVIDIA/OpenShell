// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! How `sandbox connect` supervises the `ssh` process it attaches through:
//! it reconnects when the SSH transport is lost, and a SIGTERM sent to the
//! CLI alone ends the `ssh` child too.
//!
//! The tests find the CLI's `ssh` and `ssh-proxy` processes in the test
//! host's `/proc`, so they need Linux. Attach behavior every driver must
//! provide is in the conformance `attach` suite.
//!
//! CI runs them on Docker only. Through a Kubernetes port-forward, the
//! reconnect can attach read-only while the old SSH session still owns input
//! (#4445).
//!
//! Ported from `e2e/rust/tests/sandbox_lifecycle.rs`.

use std::time::Duration;

use testkit::Context;

/// How long an attachment may take to show output or recover.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const ATTACH_TIMEOUT: Duration = Duration::from_secs(30);

/// Killing the `ssh-proxy` transport of an established `sandbox connect`
/// makes the CLI report the lost connection and reconnect to the same main
/// process, which then receives new input. The CLI keeps running.
#[testkit::test]
async fn connect_recovers_its_ssh_transport(cx: &mut Context) -> testkit::Result {
    #[cfg(target_os = "linux")]
    return linux::connect_recovers_its_ssh_transport(cx).await;
    #[cfg(not(target_os = "linux"))]
    return needs_linux(cx);
}

/// A SIGTERM sent to only the `sandbox connect` process, with a terminal as
/// its stdin, is forwarded to its `ssh` child. The CLI exits 143 and the
/// `ssh` child is gone.
#[testkit::test]
async fn connect_forwards_pid_targeted_termination_and_reaps_ssh(
    cx: &mut Context,
) -> testkit::Result {
    #[cfg(target_os = "linux")]
    return linux::connect_forwards_pid_targeted_termination_and_reaps_ssh(cx).await;
    #[cfg(not(target_os = "linux"))]
    return needs_linux(cx);
}

#[cfg(not(target_os = "linux"))]
fn needs_linux(_cx: &Context) -> testkit::Result {
    Err(testkit::Error::msg(
        "this test reads the CLI's processes from /proc and needs a Linux test host",
    ))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::OwnedFd;
    use std::process::Stdio;
    use std::time::Duration;

    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;
    use testkit::{Context, ResultExt as _, Sandbox};

    use super::ATTACH_TIMEOUT;

    /// How long the CLI treats a new attachment as still connecting. A lost
    /// transport after that is one it recovers from.
    const ESTABLISHED: Duration = Duration::from_secs(3);

    /// A main process that prints a numbered line every 0.2 seconds and
    /// echoes each line of its input.
    const ECHO_MAIN: &str = r#"trap 'kill "$writer" 2>/dev/null || true' EXIT; (n=1; while true; do printf 'transport_pid=%s sequence=%04d\n' "$$" "$n"; n=$((n + 1)); sleep 0.2; done) & writer=$!; while IFS= read -r line; do printf 'transport_pid=%s input=%s\n' "$$" "$line"; done"#;

    pub(super) async fn connect_recovers_its_ssh_transport(cx: &mut Context) -> testkit::Result {
        let sandbox = ready_sandbox(cx, "tr", &["sh", "-lc", ECHO_MAIN]).await?;
        let mut connect = cx.cli_spawn(["sandbox", "connect", sandbox.name()])?;
        let first = connect.stdout_line(ATTACH_TIMEOUT).await?;
        testkit::ensure!(
            first.contains("transport_pid="),
            "unexpected attachment output {first:?}"
        );

        // Recovery starts only for an established attachment.
        tokio::time::sleep(ESTABLISHED).await;
        let proxy = wait_for_process(
            &format!("the ssh-proxy of sandbox {}", sandbox.name()),
            || find_process(None, &["ssh-proxy", "--sandbox", sandbox.name()]),
        )
        .await?;
        send(proxy, Signal::SIGTERM).context("terminate the ssh-proxy transport")?;
        connect
            .stderr_until(ATTACH_TIMEOUT, |line| {
                line.contains("Connection to sandbox lost; reconnecting")
            })
            .await
            .context("the CLI reports the lost transport")?;

        let token = format!("after-transport-recovery-{}", cx.run_id());
        connect
            .write_stdin(format!("{token}\n").as_bytes())
            .await
            .context("send input after recovery")?;
        connect
            .stdout_until(ATTACH_TIMEOUT, |line| {
                line.contains(&format!("input={token}"))
            })
            .await
            .context("the reconnected attachment reaches the main process")?;
        testkit::ensure!(
            connect.try_wait()?.is_none(),
            "`{}` exited after recovering",
            connect.command()
        );
        connect.kill().await
    }

    pub(super) async fn connect_forwards_pid_targeted_termination_and_reaps_ssh(
        cx: &mut Context,
    ) -> testkit::Result {
        let sandbox = ready_sandbox(cx, "term", &["sh", "-lc", "exec sleep infinity"]).await?;
        let pty = nix::pty::openpty(None, None)
            .map_err(std::io::Error::from)
            .context("open a pseudo-terminal")?;
        // Held until the end, so the terminal stays open.
        let _controller: OwnedFd = pty.master;
        let mut connect = cx.cli_spawn_with_stdin(
            ["sandbox", "connect", sandbox.name()],
            Stdio::from(pty.slave),
        )?;
        let connect_pid = connect.pid();

        let ssh = wait_for_process(&format!("the ssh child of `{}`", connect.command()), || {
            find_process(Some(connect_pid), &["-s", "sandbox", "openshell-main"])
        })
        .await?;
        send(connect_pid, Signal::SIGTERM).context("send SIGTERM to only the CLI")?;
        let code = connect.wait(Duration::from_secs(10)).await?;
        testkit::ensure!(
            code == 143,
            "`{}` exited with {code} on SIGTERM; expected 143",
            connect.command()
        );
        testkit::poll_until(
            &format!("ssh process {ssh} to be gone"),
            Duration::from_secs(5),
            Duration::from_millis(25),
            async || {
                Ok(if std::fs::metadata(format!("/proc/{ssh}")).is_ok() {
                    testkit::Poll::Pending(format!("/proc/{ssh} still exists"))
                } else {
                    testkit::Poll::Ready(())
                })
            },
        )
        .await
    }

    async fn ready_sandbox(
        cx: &Context,
        suffix: &str,
        command: &[&str],
    ) -> testkit::Result<Sandbox> {
        cx.sandbox(suffix)
            .command(command.iter().copied())
            .create_ready()
            .await
    }

    fn send(pid: u32, signal: Signal) -> testkit::Result {
        let pid = i32::try_from(pid)
            .map_err(|error| testkit::Error::msg(format!("pid {pid}: {error}")))?;
        kill(Pid::from_raw(pid), signal)
            .map_err(std::io::Error::from)
            .context(format!("send {signal} to {pid}"))
    }

    async fn wait_for_process(
        what: &str,
        mut find: impl FnMut() -> Option<u32>,
    ) -> testkit::Result<u32> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(pid) = find() {
                return Ok(pid);
            }
            testkit::ensure!(
                tokio::time::Instant::now() < deadline,
                "{what} did not start"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// A process whose arguments include all of `args`, and whose parent is
    /// `parent` if given.
    fn find_process(parent: Option<u32>, args: &[&str]) -> Option<u32> {
        for entry in std::fs::read_dir("/proc").ok()?.filter_map(Result::ok) {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            if let Some(parent) = parent {
                let status =
                    std::fs::read_to_string(entry.path().join("status")).unwrap_or_default();
                let ppid = status.lines().find_map(|line| {
                    line.strip_prefix("PPid:")
                        .and_then(|value| value.trim().parse::<u32>().ok())
                });
                if ppid != Some(parent) {
                    continue;
                }
            }
            let cmdline = std::fs::read(entry.path().join("cmdline")).unwrap_or_default();
            let argv: Vec<&[u8]> = cmdline.split(|byte| *byte == 0).collect();
            if args.iter().all(|arg| argv.contains(&arg.as_bytes())) {
                return Some(pid);
            }
        }
        None
    }
}
