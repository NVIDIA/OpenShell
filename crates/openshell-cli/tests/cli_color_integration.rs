// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end checks that `openshell` does not write ANSI escape sequences into
//! a pipe.
//!
//! `Command::output` gives the child a pipe rather than a terminal, which is
//! exactly the situation these tests care about: a supervisor script parsing
//! output. The unit tests in `color` cover the precedence rules; these cover the
//! wiring from flag to rendered byte, across both styling paths that reach
//! stdout — the styled tables and the `tracing` formatter.

#![cfg(unix)]

use std::path::Path;
use std::process::Command;

const ESC: char = '\u{1b}';
const SANDBOX: &str = "openclaw-saw";
const PORT: u16 = 8443;

/// Seed a forward PID file so `forward list` has a row to render.
///
/// The PID is one that cannot be running, so the row reports `dead`. Status text
/// is irrelevant here — both states go through the same styling path.
fn config_dir_with_forward(root: &Path) {
    let forwards = root.join("openshell").join("forwards");
    std::fs::create_dir_all(&forwards).expect("create forwards dir");
    std::fs::write(
        forwards.join(format!("{SANDBOX}-{PORT}.pid")),
        // Format: <pid>\t<sandbox_id>\t<bind_addr>
        "4000000\tsbx-test\t0.0.0.0",
    )
    .expect("write forward pid file");
}

fn forward_list(config_dir: &Path, args: &[&str], no_color: Option<&str>) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args(["forward", "list"])
        .args(args)
        .env("XDG_CONFIG_HOME", config_dir)
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("OPENSHELL_COLOR");
    if let Some(value) = no_color {
        command.env("NO_COLOR", value);
    }

    let output = command.output().expect("run openshell forward list");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");
    assert!(
        stdout.contains(SANDBOX),
        "expected the seeded forward in the table, got: {stdout:?}"
    );
    stdout
}

#[test]
fn piped_output_is_free_of_escape_sequences_by_default() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let stdout = forward_list(tmpdir.path(), &[], None);

    assert!(
        !stdout.contains(ESC),
        "piped `forward list` must not emit ANSI escapes, got: {stdout:?}"
    );
}

#[test]
fn no_color_environment_variable_is_honored() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let stdout = forward_list(tmpdir.path(), &[], Some("1"));

    assert!(!stdout.contains(ESC), "NO_COLOR ignored, got: {stdout:?}");
}

#[test]
fn color_never_suppresses_escape_sequences() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let stdout = forward_list(tmpdir.path(), &["--color", "never"], None);

    assert!(
        !stdout.contains(ESC),
        "--color never ignored, got: {stdout:?}"
    );
}

#[test]
fn color_always_emits_escape_sequences_into_a_pipe() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    // The opt-in escape hatch for callers who pipe into a pager and still want
    // styling. Also proves the other cases are suppressing real output rather
    // than rendering an empty table.
    let stdout = forward_list(tmpdir.path(), &["--color", "always"], None);

    assert!(
        stdout.contains(ESC),
        "--color always must still colorize, got: {stdout:?}"
    );
}

#[test]
fn explicit_color_flag_overrides_no_color() {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let stdout = forward_list(tmpdir.path(), &["--color", "always"], Some("1"));

    assert!(
        stdout.contains(ESC),
        "--color always must outrank NO_COLOR, got: {stdout:?}"
    );
}

/// Run a command that fails to connect, with logging turned up so the `tracing`
/// formatter produces output.
///
/// `tracing_subscriber::fmt` writes to stdout with ANSI enabled and does no
/// terminal detection of its own, so this is a second, independent way for
/// escapes to reach a pipe.
fn failing_connect(args: &[&str]) -> (String, String) {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let output = Command::new(env!("CARGO_BIN_EXE_openshell"))
        .args([
            "sandbox",
            "list",
            "--gateway",
            "test-gateway",
            // Nothing listens on port 1; the connection is refused immediately.
            "--gateway-endpoint",
            "http://127.0.0.1:1",
        ])
        .args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("RUST_LOG", "debug")
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("OPENSHELL_COLOR")
        .output()
        .expect("run openshell sandbox list");

    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn verbose_log_output(args: &[&str]) -> String {
    failing_connect(args).0
}

#[test]
fn tracing_output_is_free_of_escape_sequences_when_piped() {
    let plain = verbose_log_output(&[]);
    let styled = verbose_log_output(&["--color", "always"]);

    // Positive control. If this fails, the command stopped emitting logs at
    // debug level — fix the invocation rather than deleting the assertion
    // below, which would otherwise pass vacuously.
    assert!(
        styled.contains(ESC),
        "expected `--color always` to style log output; got: {styled:?}"
    );
    assert!(
        !plain.contains(ESC),
        "piped log output must not emit ANSI escapes, got: {plain:?}"
    );
}

/// Run a command with stdout attached to a pseudo-terminal and stderr on a
/// pipe, returning what each stream received.
#[cfg(target_os = "linux")]
fn run_with_stdout_tty(mut command: Command) -> (String, String) {
    use std::io::Read;
    use std::os::fd::{AsRawFd, OwnedFd};

    let pty = nix::pty::openpty(None, None).expect("openpty");
    let controller: OwnedFd = pty.master;
    let follower: OwnedFd = pty.slave;

    let mut child = command
        .stdout(follower.try_clone().expect("dup pty follower"))
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn openshell");
    // `Command` retains its configured stdio handles after spawning. Drop it so
    // the controller sees EIO once the child exits.
    drop(command);

    // Drop every follower handle in this process, or reading the controller
    // blocks forever instead of returning EIO once the child exits.
    drop(follower);

    let mut stderr_buf = String::new();
    child
        .stderr
        .take()
        .expect("stderr pipe")
        .read_to_string(&mut stderr_buf)
        .expect("read stderr");
    child.wait().expect("wait for openshell");

    // The pty read ends with EIO rather than a clean EOF; treat that as done.
    let mut stdout_buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match nix::unistd::read(controller.as_raw_fd(), &mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => stdout_buf.extend_from_slice(&chunk[..n]),
        }
    }

    (
        String::from_utf8_lossy(&stdout_buf).into_owned(),
        stderr_buf,
    )
}

/// Run a failing command with stdout attached to a pseudo-terminal and stderr
/// on a pipe, returning what each stream received.
///
/// `Command::output` gives both streams pipes, so it cannot distinguish a
/// per-stream decision from a single one resolved off stdout. This asymmetric
/// setup is the only way to catch a stream being handed the other stream's
/// answer.
#[cfg(target_os = "linux")]
fn split_streams_stdout_tty(args: &[&str]) -> (String, String) {
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args([
            "sandbox",
            "list",
            "--gateway",
            "test-gateway",
            "--gateway-endpoint",
            "http://127.0.0.1:1",
        ])
        .args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("RUST_LOG", "debug")
        // Pin TERM: `auto` now requires a capable terminal, and CI runners
        // often leave TERM unset, which would make this test's outcome depend
        // on the ambient environment.
        .env("TERM", "xterm-256color")
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("OPENSHELL_COLOR");

    run_with_stdout_tty(command)
}

/// Run `forward list` with stdout on a pseudo-terminal, under the given `TERM`,
/// and return everything stdout received.
///
/// When `stderr_on_tty` is true, both streams share the terminal so the
/// `owo-colors` table is styled too. Otherwise, stderr is redirected to
/// `/dev/null`, which verifies the conservative table behavior.
#[cfg(target_os = "linux")]
fn forward_list_on_pty(term: &str, args: &[&str], stderr_on_tty: bool) -> String {
    use std::os::fd::{AsRawFd, OwnedFd};

    let pty = nix::pty::openpty(None, None).expect("openpty");
    let controller: OwnedFd = pty.master;
    let follower: OwnedFd = pty.slave;

    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let mut command = Command::new(env!("CARGO_BIN_EXE_openshell"));
    command
        .args(["forward", "list"])
        .args(args)
        .env("XDG_CONFIG_HOME", tmpdir.path())
        .env("TERM", term)
        .env_remove("NO_COLOR")
        .env_remove("FORCE_COLOR")
        .env_remove("OPENSHELL_COLOR")
        .stdout(follower.try_clone().expect("dup pty follower"));
    if stderr_on_tty {
        command.stderr(follower.try_clone().expect("dup pty follower"));
    } else {
        command.stderr(std::process::Stdio::null());
    }
    let mut child = command.spawn().expect("spawn openshell");
    // `Command` retains its configured stdio handles after spawning. Drop it so
    // the controller sees EIO once the child exits.
    drop(command);

    // Drop every follower handle here, or the controller read never sees EIO.
    drop(follower);

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match nix::unistd::read(controller.as_raw_fd(), &mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    child.wait().expect("wait for openshell");

    let out = String::from_utf8_lossy(&buf).into_owned();
    assert!(
        out.contains(SANDBOX),
        "expected the seeded forward in the table, got: {out:?}"
    );
    out
}

/// A terminal that does not render ANSI must not be styled under `auto`.
///
/// `TERM=dumb` is still a terminal, so an `is_terminal()` check alone reports it
/// as styleable. `console` and `miette` apply their own `TERM` checks, but the
/// color switch overrides both, so the check has to live here.
#[cfg(target_os = "linux")]
#[test]
fn dumb_terminal_is_not_styled_under_auto() {
    let dumb = forward_list_on_pty("dumb", &[], true);
    // Positive control: the same session on a capable terminal is styled, so a
    // plain result below means capability was consulted, not that the pty setup
    // silently produced nothing.
    let capable = forward_list_on_pty("xterm-256color", &[], true);

    assert!(
        capable.contains(ESC),
        "expected styling on a capable terminal; got: {capable:?}"
    );
    assert!(
        !dumb.contains(ESC),
        "TERM=dumb must not be styled, got: {dumb:?}"
    );
}

/// An explicit request outranks the capability check, for callers who know
/// their terminal better than `TERM` does.
#[cfg(target_os = "linux")]
#[test]
fn color_always_overrides_a_dumb_terminal() {
    let forced = forward_list_on_pty("dumb", &["--color", "always"], true);

    assert!(
        forced.contains(ESC),
        "--color always must style even a dumb terminal, got: {forced:?}"
    );
}

/// Regression test for a redirected stream inheriting the other stream's
/// terminal check.
///
/// With stdout on a terminal and stderr redirected, `openshell ... 2> build.log`
/// must leave the log free of escapes while stdout stays styled.
#[cfg(target_os = "linux")]
#[test]
fn redirected_stderr_stays_plain_while_stdout_is_a_terminal() {
    let (stdout, stderr) = split_streams_stdout_tty(&[]);

    // Positive control: stdout really is a terminal here, so something must be
    // styled. Otherwise the stderr assertion could pass for the wrong reason.
    assert!(
        stdout.contains(ESC),
        "expected styled stdout on a pty; got: {stdout:?}"
    );
    assert!(
        !stderr.contains(ESC),
        "redirected stderr must not receive escapes, got: {stderr:?}"
    );
}

/// `Painted` cannot identify its destination stream, so table styling is
/// deliberately disabled when either stream is redirected.
#[cfg(target_os = "linux")]
#[test]
fn status_table_is_plain_when_stderr_is_redirected() {
    let stdout = forward_list_on_pty("xterm-256color", &[], false);

    assert!(
        stdout.contains(SANDBOX),
        "expected the seeded forward in the table, got: {stdout:?}"
    );
    assert!(
        !stdout.contains(ESC),
        "STATUS table must stay plain when stderr is redirected, got: {stdout:?}"
    );
}

#[test]
fn error_output_follows_the_color_setting() {
    // miette renders errors to stderr through its own handler. It already
    // suppresses color when stderr is redirected, but it has no way to learn
    // about `--color`, so `init` installs a handler built from the setting.
    let (_, plain) = failing_connect(&[]);
    let (_, styled) = failing_connect(&["--color", "always"]);

    assert!(
        styled.contains(ESC),
        "expected `--color always` to style error output; got: {styled:?}"
    );
    assert!(
        !plain.contains(ESC),
        "piped error output must not emit ANSI escapes, got: {plain:?}"
    );
}

#[test]
fn status_column_is_matchable_by_a_whitespace_anchored_pattern() {
    // The regression this whole change exists for: a supervisor deciding whether
    // a forward is alive by matching the STATUS column. Colorized output put an
    // escape byte immediately before the status word, so a pattern requiring
    // whitespace ahead of it could never match.
    let tmpdir = tempfile::tempdir().expect("create tmpdir");
    config_dir_with_forward(tmpdir.path());

    let stdout = forward_list(tmpdir.path(), &[], None);
    let row = stdout
        .lines()
        .find(|line| line.starts_with(SANDBOX))
        .unwrap_or_else(|| panic!("no row for {SANDBOX} in: {stdout:?}"));

    let status = row
        .split_whitespace()
        .next_back()
        .expect("row has a status column");
    assert_eq!(status, "dead");

    // Whitespace, not an escape byte, separates the PID from the status.
    let boundary = row
        .rfind(status)
        .and_then(|index| row[..index].chars().next_back())
        .expect("status is preceded by the rest of the row");
    assert!(
        boundary.is_whitespace(),
        "expected whitespace before the status column, found {boundary:?} in {row:?}"
    );
}
