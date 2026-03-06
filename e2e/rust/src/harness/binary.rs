// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI binary resolution for e2e tests.
//!
//! Resolves the `nemoclaw` binary at `<workspace>/target/debug/nemoclaw`.
//! The binary must already be built — the `e2e:rust` mise task handles
//! this by running `cargo build -p navigator-cli` before the tests.

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

/// Return the path to the `nemoclaw` CLI binary.
///
/// Expects the binary at `<workspace>/target/debug/nemoclaw`.
///
/// # Panics
///
/// Panics if the binary is not found. Run `cargo build -p navigator-cli`
/// (or `mise run e2e:rust`) first.
pub fn nemoclaw_bin() -> PathBuf {
    let bin = workspace_root().join("target/debug/nemoclaw");
    assert!(
        bin.is_file(),
        "nemoclaw binary not found at {bin:?} — run `cargo build -p navigator-cli` first"
    );
    bin
}

/// Create a [`tokio::process::Command`] pre-configured to invoke the
/// `nemoclaw` CLI.
///
/// The command has `kill_on_drop(true)` set so that background child processes
/// are cleaned up when the handle is dropped.
pub fn nemoclaw_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(nemoclaw_bin());
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
