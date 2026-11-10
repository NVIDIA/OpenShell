// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `sandbox exec` through the `openshell` CLI: large output, piped stdin, and
//! early exit.
//!
//! Ported from `e2e/rust/tests/sandbox_lifecycle.rs`.

use std::time::Duration;

use testkit::{Context, ResultExt as _, Sandbox};

/// How long one exec of a few MiB may take.
const EXEC_TIMEOUT: Duration = Duration::from_secs(30);
/// The largest stdin a non-interactive exec accepts.
const STDIN_LIMIT: usize = 4 * 1024 * 1024;

/// `sandbox exec --no-tty` returns all of a large stdout and stderr, exits 0
/// when the command exits before reading all its stdin, and doesn't wait for
/// a background process that still holds the output pipe.
#[testkit::test]
async fn cli_exec_large_output_is_complete(cx: &mut Context) -> testkit::Result {
    const BYTES: usize = 8 * 1024 * 1024;
    let sandbox = ready_sandbox(cx, "lo").await?;

    for stream in ["stdout", "stderr"] {
        let script = match stream {
            "stdout" => format!("yes A | head -c {BYTES}"),
            _ => format!("yes A | head -c {BYTES} >&2"),
        };
        let output = tokio::time::timeout(
            EXEC_TIMEOUT,
            cx.cli(exec_args(&sandbox, &["sh", "-c", &script])),
        )
        .await
        .map_err(|_| testkit::Error::msg(format!("exec of 8 MiB on {stream} timed out")))??
        .success()?;
        let bytes = match stream {
            "stdout" => output.stdout.as_bytes(),
            _ => output.stderr.as_bytes(),
        };
        testkit::ensure!(
            bytes.len() == BYTES,
            "exec {stream} has {} bytes; expected {BYTES}",
            bytes.len()
        );
        testkit::ensure!(
            bytes.chunks_exact(2).all(|pair| pair == b"A\n"),
            "exec {stream} differs from the `yes A` output"
        );
    }

    let mut early_exit = cx.cli_spawn(exec_args(&sandbox, &["head", "-n1"]))?;
    let mut input = b"first\n".to_vec();
    input.extend(vec![b'x'; 128 * 1024]);
    if let Err(error) = early_exit.write_stdin(&input).await {
        testkit::ensure!(
            error.kind() == std::io::ErrorKind::BrokenPipe,
            "write stdin of `{}`: {error}",
            early_exit.command()
        );
    }
    let output = early_exit.output(EXEC_TIMEOUT).await?.success()?;
    testkit::ensure!(
        output.stdout == "first\n",
        "`head -n1` printed {:?}; expected \"first\\n\"",
        output.stdout
    );

    let output = tokio::time::timeout(
        Duration::from_secs(10),
        cx.cli(exec_args(&sandbox, &["sh", "-c", "sleep 5 & echo ok"])),
    )
    .await
    .map_err(|_| testkit::Error::msg("exec waited for a background process holding its output"))??
    .success()?;
    testkit::ensure!(
        output.stdout == "ok\n",
        "exec printed {:?}; expected \"ok\\n\"",
        output.stdout
    );
    Ok(())
}

/// Piped stdin larger than one gRPC message reaches the command intact, up to
/// the 4 MiB limit. A larger stdin is rejected with a message naming the
/// limit, a forced TTY with piped stdin still works, and a stdin that can't be
/// read fails the exec.
#[testkit::test]
async fn cli_exec_piped_stdin_crosses_grpc_message_limit(cx: &mut Context) -> testkit::Result {
    let sandbox = ready_sandbox(cx, "si").await?;
    let wc = exec_args(&sandbox, &["wc", "-c"]);

    for size in [5, 1024 * 1024, STDIN_LIMIT] {
        let mut exec = cx.cli_spawn(&wc)?;
        exec.write_stdin(&vec![b'x'; size])
            .await
            .context(format!("write {size} bytes to `{}`", exec.command()))?;
        let output = exec.output(EXEC_TIMEOUT).await?.success()?;
        testkit::ensure!(
            output.stdout.trim() == size.to_string(),
            "`wc -c` counted {:?} of {size} piped bytes",
            output.stdout.trim()
        );
    }

    let mut oversized = cx.cli_spawn(&wc)?;
    oversized
        .write_stdin(&vec![b'x'; STDIN_LIMIT + 1])
        .await
        .context(format!(
            "write oversized stdin to `{}`",
            oversized.command()
        ))?;
    let output = oversized.output(EXEC_TIMEOUT).await?.failure()?;
    testkit::ensure!(
        output.stdout.is_empty(),
        "an exec with oversized stdin printed {:?}",
        output.stdout
    );
    testkit::ensure!(
        output.stderr.contains("4 MiB limit"),
        "an exec with oversized stdin did not name the limit; stderr: {}",
        output.stderr.trim()
    );

    // A forced PTY with a small pipe must keep using the unary RPC for
    // compatibility with older gateways.
    let mut tty = cx.cli_spawn([
        "sandbox",
        "exec",
        "--name",
        sandbox.name(),
        "--tty",
        "--no-login-shell",
        "--",
        "sh",
        "-c",
        "printf tty-ok",
    ])?;
    tty.write_stdin(b"x")
        .await
        .context(format!("write stdin to `{}`", tty.command()))?;
    let output = tty.output(EXEC_TIMEOUT).await?.success()?;
    testkit::ensure!(
        output.stdout.contains("tty-ok"),
        "a forced TTY exec printed {:?}",
        output.stdout
    );

    #[cfg(unix)]
    {
        let directory = std::fs::File::open("/").context("open / as stdin")?;
        let output = cx
            .cli_spawn_with_stdin(&wc, directory)?
            .output(EXEC_TIMEOUT)
            .await?
            .failure()?;
        testkit::ensure!(
            output.stdout.is_empty(),
            "an exec whose stdin can't be read printed {:?}",
            output.stdout
        );
    }
    Ok(())
}

async fn ready_sandbox(cx: &Context, suffix: &str) -> testkit::Result<Sandbox> {
    cx.sandbox(suffix)
        .command(["sleep", "infinity"])
        .create_ready()
        .await
}

/// `sandbox exec` of `command` without a TTY or login shell.
fn exec_args(sandbox: &Sandbox, command: &[&str]) -> Vec<String> {
    [
        "sandbox",
        "exec",
        "--name",
        sandbox.name(),
        "--no-tty",
        "--no-login-shell",
        "--",
    ]
    .iter()
    .chain(command)
    .map(ToString::to_string)
    .collect()
}
