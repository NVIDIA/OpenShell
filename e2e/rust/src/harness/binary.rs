// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI binary resolution for e2e tests.
//!
//! Resolves the `ryno` binary from `RYNO_BIN`, or from
//! `<workspace>/target/debug/ryno` for local runs. The local binary must
//! already be built — the E2E mise tasks do this before running the tests.

use std::path::{Path, PathBuf};

/// Locate the workspace root by walking up from the crate's manifest directory.
fn workspace_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    // e2e/rust/ is two levels below the workspace root.
    manifest_dir
        .ancestors()
        .nth(2)
        .expect("failed to resolve workspace root from CARGO_MANIFEST_DIR")
        .to_path_buf()
}

/// Return the path to the `ryno` CLI binary.
///
/// Uses `RYNO_BIN` when set, otherwise expects the binary at
/// `<workspace>/target/debug/ryno`.
///
/// # Panics
///
/// Panics if the configured or locally-built binary is not found.
pub fn ryno_bin() -> PathBuf {
    let bin = std::env::var_os("RYNO_BIN").map_or_else(
        || workspace_root().join("target/debug/ryno"),
        PathBuf::from,
    );
    assert!(
        bin.is_file(),
        "ryno binary not found at {} — set RYNO_BIN or run `cargo build -p ryno-cli` first",
        bin.display()
    );
    bin
}

/// Create a [`tokio::process::Command`] pre-configured to invoke the
/// `ryno` CLI.
///
/// The command has `kill_on_drop(true)` set so that background child processes
/// are cleaned up when the handle is dropped.
pub fn ryno_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(ryno_bin());
    cmd.kill_on_drop(true);
    cmd
}

fn shell_escape(arg: &str) -> String {
    if arg
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_./:@".contains(c))
    {
        return arg.to_string();
    }

    format!("'{}'", arg.replace('\'', "'\\''"))
}

/// Create a [`tokio::process::Command`] that runs `ryno` under a PTY.
pub fn ryno_tty_cmd(args: &[&str]) -> tokio::process::Command {
    let bin = ryno_bin();
    let mut cmd = tokio::process::Command::new("script");

    if cfg!(target_os = "macos") {
        cmd.arg("-q").arg("/dev/null").arg(bin).args(args);
    } else {
        let mut shell_command = shell_escape(bin.to_str().expect("ryno path is utf-8"));
        for arg in args {
            shell_command.push(' ');
            shell_command.push_str(&shell_escape(arg));
        }
        cmd.arg("-q")
            .arg("-e")
            .arg("-c")
            .arg(shell_command)
            .arg("/dev/null");
    }

    cmd.kill_on_drop(true);
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_root_resolves() {
        let root = workspace_root();
        assert!(
            root.join("Cargo.toml").is_file(),
            "workspace root should contain Cargo.toml: {root:?}"
        );
    }
}
