// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Process execution boundary for the CLI conformance runner.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Output, Stdio};
use std::time::Duration;

use tokio::time::timeout;

pub type CliExecution<'a> =
    Pin<Box<dyn Future<Output = Result<Output, CliExecutionError>> + Send + 'a>>;

pub trait CliExecutor: Send + Sync {
    fn execute(&self, args: Vec<String>, command_timeout: Duration) -> CliExecution<'_>;
}

pub enum CliExecutionError {
    Spawn(std::io::Error),
    Timeout,
}

pub struct ProcessCli {
    binary: PathBuf,
}

impl ProcessCli {
    pub fn new(binary: PathBuf) -> Self {
        Self { binary }
    }
}

impl CliExecutor for ProcessCli {
    fn execute(&self, args: Vec<String>, command_timeout: Duration) -> CliExecution<'_> {
        Box::pin(async move {
            let mut process = tokio::process::Command::new(&self.binary);
            process
                .args(&args)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);

            timeout(command_timeout, process.output())
                .await
                .map_err(|_| CliExecutionError::Timeout)?
                .map_err(CliExecutionError::Spawn)
        })
    }
}
