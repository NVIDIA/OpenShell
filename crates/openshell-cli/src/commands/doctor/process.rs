// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bounded command execution shared by prerequisite providers.

use miette::{IntoDiagnostic, Result, WrapErr, miette};
use std::path::Path;
use std::process::Output;
use std::time::Duration;
use tokio::process::Command;

pub(super) async fn command_output(
    program: &Path,
    args: &[&str],
    timeout: Duration,
) -> Result<Output> {
    tokio::time::timeout(
        timeout,
        Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .map_err(|_| {
        miette!(
            "Prerequisite command timed out after {} seconds",
            timeout.as_secs()
        )
    })?
    .into_diagnostic()
    .wrap_err("failed to execute prerequisite command")
}
